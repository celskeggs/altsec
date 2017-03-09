#include <unistd.h>
#include <libnotify/notify.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct cb_params {
    bool result;
    GMainLoop *main_loop;
};

bool result = false;

void callback(NotifyNotification *notification, char *action, gpointer user_data) {
    struct cb_params *p = (struct cb_params *) user_data;
    p->result = (strcmp(action, "accept") == 0);
    g_main_loop_quit(p->main_loop);
}

gboolean cancel(gpointer ptr) {
    g_main_loop_quit((GMainLoop *) ptr);
    return FALSE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fputs("Too few arguments.\n", stderr);
        return 1;
    }
    if (getuid() != 0) {
        // need to run sudo to get root
        char **new_argv = malloc(sizeof(char *) * (argc + 3));
        new_argv[0] = "sudo";
        new_argv[1] = "--";
        for (int i = 0; i < argc; i++) {
            new_argv[2 + i] = argv[i];
        }
        new_argv[argc + 2] = NULL;
        execvp("sudo", new_argv);
        // oh no! it failed.
        perror("execvp");
        return 1;
    }

    notify_init("altsec");

    GMainLoop *loop = g_main_loop_new(g_main_context_default(), true);

    NotifyNotification *Hello = notify_notification_new("Root Request", "Accept or deny root access",
                                                        "dialog-authentication");
    notify_notification_set_timeout(Hello, 5000);
    struct cb_params params = {false, loop};
    notify_notification_add_action(Hello, "accept", "Accept", callback, &params, NULL);
    notify_notification_add_action(Hello, "default", "Deny", callback, &params, NULL);
    notify_notification_show(Hello, NULL);
    g_timeout_add_seconds(5, cancel, loop);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    g_object_unref(G_OBJECT(Hello));
    notify_uninit();

    if (params.result) {
        execvp(argv[1], argv + 1);
        // oh no! it failed.
        perror("execvp");
        return 1;
    } else {
        fputs("denied", stderr);
        return 1;
    }
}
