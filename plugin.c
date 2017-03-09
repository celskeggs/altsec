/*
 * Based on sample plugin code for sudo.
 *
 * Copyright (c) 2016 Cel Skeggs <public@celskeggs.com>
 * Copyright (c) 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sudo_plugin.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#define EXPECTED_SUDO_MAJOR 1
#define EXPECTED_SUDO_MINOR 9
#define ALTSEC_VER "0.1"

#if SUDO_API_VERSION_MAJOR != EXPECTED_SUDO_MAJOR
#error Wrong sudo API version: expected major number of 1
#endif
#if SUDO_API_VERSION_MINOR < EXPECTED_SUDO_MINOR
#error Wrong sudo API version: expected minor number of at least 9
#endif

static sudo_conv_t p_conversation;
static sudo_printf_t p_printf;
static uid_t p_uid = 0;
static bool p_use_gid = false;
static bool p_sudoedit = false;
static gid_t p_gid;
static char *const *p_user_env = NULL;
static char *const *p_settings = NULL;
static char *const *p_user_info = NULL;

static int
policy_open(unsigned int version, sudo_conv_t conversation, sudo_printf_t plugin_printf, char *const settings[],
            char *const user_info[], char *const user_env[], char *const plugin_plugins[]) {
    p_conversation = conversation;
    p_printf = plugin_printf;
    if (SUDO_API_VERSION_GET_MAJOR(version) != EXPECTED_SUDO_MAJOR ||
        SUDO_API_VERSION_GET_MINOR(version) < EXPECTED_SUDO_MINOR) {
        plugin_printf(SUDO_CONV_ERROR_MSG, "Invalid sudo plugin API version. Expected %d.%d or compatible.\n",
                      EXPECTED_SUDO_MAJOR, EXPECTED_SUDO_MINOR);
        return -1;
    }
// && is just for chaining - I don't expect the second operand to evaluate to false
#define IF_SETTING(check) if (strncmp(*setting, check "=", sizeof(check)) == 0 && (param = *setting + sizeof(check)))
#define IF_TRUE() if (strcasecmp(param, "true") == 0)
    for (char *const *setting = settings; *setting; setting++) {
        char *param;
        IF_SETTING("runas_user") {
            struct passwd *pw = getpwnam(param);
            if (pw == NULL) {
                p_printf(SUDO_CONV_ERROR_MSG, "unknown user %s\n", param);
                return 0;
            }
            p_uid = pw->pw_uid;
        }
        IF_SETTING("runas_group") {
            struct group *gr = getgrnam(param);
            if (gr == NULL) {
                p_printf(SUDO_CONV_ERROR_MSG, "unknown group %s\n", param);
                return 0;
            }
            p_use_gid = true;
            p_gid = gr->gr_gid;
        }
        IF_SETTING("sudoedit") {
            IF_TRUE() {
                p_sudoedit = true;
            }
        }
        IF_SETTING("ignore_ticket") {
            IF_TRUE() {
                p_printf(SUDO_CONV_ERROR_MSG, "cannot ignore cached credentials.\n");
                return -1;
            }
        }
        IF_SETTING("implied_shell") {
            IF_TRUE() {
                return -2; // usage error
            }
        }
        IF_SETTING("login_shell") {
            IF_TRUE() {
                p_printf(SUDO_CONV_ERROR_MSG, "cannot run login shells.\n");
                return -1;
            }
        }
        IF_SETTING("noninteractive") {
            IF_TRUE() {
                p_printf(SUDO_CONV_ERROR_MSG, "user interaction is required.\n");
                return -1;
            }
        }
    }
    p_user_env = user_env;
    p_settings = settings;
    p_user_info = user_info;
    return 1;
}

static void policy_close(int exit_status, int error) {
    if (error) {
        p_printf(SUDO_CONV_ERROR_MSG, "Exec error: %s\n", strerror(error));
    } else if (WIFEXITED(exit_status)) {
        p_printf(SUDO_CONV_INFO_MSG, "Exit status: %d\n", WEXITSTATUS(exit_status));
    } else if (WIFSIGNALED(exit_status)) {
        p_printf(SUDO_CONV_INFO_MSG, "Exit signal: %d\n", WTERMSIG(exit_status));
    }
}

static int policy_show_version(int verbose) {
    p_printf(SUDO_CONV_INFO_MSG, "altsec plugin version %s\n", ALTSEC_VER);
    return 1;
}


static int
policy_check_policy(int argc, char *const argv[], char *env_add[], char **command_info_out[], char **argv_out[],
                    char **user_env_out[]) {
    if (!argc || argv[0] == NULL) {
        p_printf(SUDO_CONV_ERROR_MSG, "no command specified\n");
        return 0;
    }

    if (!check_passwd()) {
        return false;
    }

    char *command = find_in_path(argv[0], plugin_state.envp);
    if (command == NULL) {
        p_printf(SUDO_CONV_ERROR_MSG, "%s: command not found\n", argv[0]);
        return false;
    }

    if (p_sudoedit) {
        /* Rebuild argv using editor */
        free(command);
        command = find_editor(argc - 1, argv + 1, argv_out);
        if (command == NULL) {
            p_printf(SUDO_CONV_ERROR_MSG, "unable to find valid editor\n");
            return -1;
        }
        use_sudoedit = true;
    } else {
        /* No changes needed to argv */
        *argv_out = (char **) argv;
    }

    /* No changes to envp */
    *user_env_out = (char**) p_user_env;

    /* Setup command info. */
    *command_info_out = build_command_info(command);
    free(command);
    if (*command_info_out == NULL) {
        p_printf(SUDO_CONV_ERROR_MSG, "OOM\n");
        return -1;
    }

    return true;
}

static int policy_list(int argc, char *const argv[], int verbose, const char *list_user) {

}

static int policy_validate(void) {

}

static void policy_invalidate(int remove) {

}

static int policy_init_session(struct passwd *pwd, char **user_env_out[]) {

}

static void policy_register_hooks(int version, int (*register_hook)(struct sudo_hook *hook)) {

}

static void policy_deregister_hooks(int version, int (*deregister_hook)(struct sudo_hook *hook)) {

}

struct policy_plugin notify_policy = {
        .type = SUDO_POLICY_PLUGIN,
        .version = SUDO_API_VERSION,
        .open = policy_open,
        .close = policy_close,
        .show_version = policy_show_version,
        .check_policy = policy_check_policy,
        .list = policy_list,
        .validate = policy_validate,
        .invalidate = policy_invalidate,
        .init_session = policy_init_session,
        .register_hooks = policy_register_hooks,
        .deregister_hooks = policy_deregister_hooks
};
