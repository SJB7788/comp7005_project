#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_convert/integer.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_string.h>
#include <p101_unix/p101_getopt.h>
#include <stdio.h>
#include <stdlib.h>

struct arguments
{
    int         argc;
    const char *program_name;
    const char *count;
    const char *message;
    char      **argv;
};

struct settings
{
    unsigned int count;
    const char  *message;
};

struct context
{
    struct arguments *arguments;
    struct settings   settings;
    int               exit_code;
    char             *exit_message;
};

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t display_messages(const struct p101_env *env, struct p101_error *err, void *arg);
static void             display_message(const struct p101_env *env, size_t iteration, const char *message);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg);

enum states
{
    PARSE_ARGS = P101_FSM_USER_START,    // 2
    HANDLE_ARGS,
    USAGE,
    DISPLAY_MESSAGES,
    CLEANUP,
};

#define UNKNOWN_OPTION_MESSAGE_LEN 24

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT,    PARSE_ARGS,       parse_arguments },
        {PARSE_ARGS,       HANDLE_ARGS,      handle_arguments},
        {PARSE_ARGS,       USAGE,            usage           },
        {HANDLE_ARGS,      DISPLAY_MESSAGES, display_messages},
        {HANDLE_ARGS,      USAGE,            usage           },
        {USAGE,            CLEANUP,          cleanup         },
        {DISPLAY_MESSAGES, CLEANUP,          cleanup         },
        {CLEANUP,          P101_FSM_EXIT,    NULL            }
    };
    struct p101_error    *error;
    struct p101_env      *env;
    struct p101_fsm_info *fsm;
    p101_fsm_state_t      from_state;
    p101_fsm_state_t      to_state;
    struct p101_error    *fsm_error;
    struct p101_env      *fsm_env;
    bool                  bad;
    bool                  will;
    bool                  did;
    struct arguments      arguments;
    struct context        context;

    error = p101_error_create(false);

    if(error == NULL)
    {
        context.exit_code = EXIT_FAILURE;
        goto done;
    }

    env = p101_env_create(error, true, NULL);

    if(p101_error_has_error(error))
    {
        context.exit_code = EXIT_FAILURE;
        goto free_error;
    }

    p101_memset(env, &arguments, 0, sizeof(arguments));
    p101_memset(env, &context, 0, sizeof(context));
    context.arguments       = &arguments;
    context.arguments->argc = argc;
    context.arguments->argv = argv;
    context.exit_code       = EXIT_SUCCESS;
    fsm_error               = p101_error_create(false);

    if(fsm_error == NULL)
    {
        context.exit_code = EXIT_FAILURE;
        goto free_env;
    }

    fsm_env = p101_env_create(error, true, NULL);

    if(p101_error_has_error(error))
    {
        context.exit_code = EXIT_FAILURE;
        goto free_fsm_error;
    }

    fsm  = p101_fsm_info_create(env, error, "application-fsm", fsm_env, fsm_error, NULL);
    bad  = false;
    will = false;
    did  = false;

    if(bad)
    {
        p101_fsm_info_set_bad_change_state_notifier(fsm, p101_fsm_info_default_bad_change_state_notifier);
    }

    if(will)
    {
        p101_fsm_info_set_will_change_state_notifier(fsm, p101_fsm_info_default_will_change_state_notifier);
    }

    if(did)
    {
        p101_fsm_info_set_did_change_state_notifier(fsm, p101_fsm_info_default_did_change_state_notifier);
    }

    p101_fsm_run(fsm, &from_state, &to_state, &context, transitions, sizeof(transitions));
    p101_fsm_info_destroy(env, &fsm);
    free(fsm_env);

free_fsm_error:
    p101_error_reset(fsm_error);
    p101_free(env, fsm_error);

free_env:
    p101_free(env, env);

free_error:
    p101_error_reset(error);
    free(error);

done:
    return context.exit_code;
}

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct context  *context;
    p101_fsm_state_t next_state;
    int              opt;

    P101_TRACE(env);
    context                          = (struct context *)arg;
    context->arguments->program_name = context->arguments->argv[0];
    next_state                       = HANDLE_ARGS;
    opterr                           = 0;

    while((opt = getopt(context->arguments->argc, context->arguments->argv, "hc:")) != -1)
    {
        switch(opt)
        {
            case 'c':
            {
                context->arguments->count = optarg;
                break;
            }
            case 'h':
            {
                next_state = USAGE;
                break;
            }
            case '?':
            {
                if(optopt == 'c')
                {
                    context->exit_message = p101_strdup(env, err, "Option '-c' requires a value.");
                }
                else
                {
                    char message[UNKNOWN_OPTION_MESSAGE_LEN];

                    snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                    context->exit_message = p101_strdup(env, err, message);
                }

                next_state = USAGE;
                break;
            }
            default:
            {
                context->exit_message = p101_strdup(env, err, "Uknown error with getopt");
                next_state            = USAGE;
            }
        }
    }

    if(next_state != USAGE)
    {
        if(optind >= context->arguments->argc)
        {
            context->exit_message = p101_strdup(env, err, "The message is required");
            next_state            = USAGE;
        }

        if(optind < context->arguments->argc - 1)
        {
            context->exit_message = p101_strdup(env, err, "Too many arguments.");
            next_state            = USAGE;
        }

        if(next_state != USAGE)
        {
            context->arguments->message = context->arguments->argv[optind];
        }
    }

    return next_state;
}

static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct context  *context;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    context    = (struct context *)arg;
    next_state = DISPLAY_MESSAGES;

    if(context->arguments->count == NULL)
    {
        context->settings.count = 1;
    }
    else
    {
        context->settings.count = p101_parse_unsigned_int(env, err, context->arguments->count, 0);

        if(p101_error_has_error(err))
        {
            context->exit_message = p101_strdup(env, err, "count must be a positive integer");
            next_state            = USAGE;
        }
        else if(context->settings.count == 0)
        {
            context->exit_message = p101_strdup(env, err, "count must be greater than 0");
            next_state            = USAGE;
        }
    }

    if(next_state != USAGE)
    {
        if(context->arguments->message == NULL)
        {
            context->exit_message = p101_strdup(env, err, "<message> must be passed.");
            next_state            = USAGE;
        }

        if(p101_strlen(env, context->arguments->message) == 0)
        {
            context->exit_message = p101_strdup(env, err, "<message> cannot be empty.");
            next_state            = USAGE;
        }

        context->settings.message = context->arguments->message;
    }

    return next_state;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct context *context;

    P101_TRACE(env);
    context = (struct context *)arg;

    if(context->exit_message != NULL)
    {
        context->exit_code = EXIT_FAILURE;
        fprintf(stderr, "%s\n", context->exit_message);
    }

    fprintf(stderr, "Usage: %s [-h] [-c <count>] <message>\n", context->arguments->program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    fputs("  -c  The number of times to display the message\n", stderr);

    return CLEANUP;
}

#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t display_messages(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct context *context;

    P101_TRACE(env);
    context = (struct context *)arg;

    for(size_t i = 1; i <= context->settings.count; i++)
    {
        display_message(env, i, context->settings.message);
    }

    return CLEANUP;
}

#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static void display_message(const struct p101_env *env, size_t iteration, const char *message)
{
    P101_TRACE(env);

    printf("[%zu] %s\n", iteration, message);
}

#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct context *context;

    P101_TRACE(env);
    context = (struct context *)arg;

    if(context->exit_message != NULL)
    {
        p101_free(env, context->exit_message);
        context->exit_message = NULL;
    }

    return P101_FSM_EXIT;
}

#pragma GCC diagnostic pop
