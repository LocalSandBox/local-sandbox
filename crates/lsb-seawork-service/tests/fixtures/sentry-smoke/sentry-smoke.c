#include <sentry.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static FILE *envelope_file;

static void write_envelope(sentry_envelope_t *envelope, void *state)
{
    (void)state;
    size_t size = 0;
    char *serialized = sentry_envelope_serialize(envelope, &size);
    if (serialized && envelope_file) {
        fwrite(serialized, 1, size, envelope_file);
        fputc('\n', envelope_file);
        fflush(envelope_file);
    }
    sentry_free(serialized);
    sentry_envelope_free(envelope);
}

static int configure(const wchar_t *database, const wchar_t *handler,
    const wchar_t *attachment, int local_transport)
{
    sentry_options_t *options = sentry_options_new();
    sentry_options_set_dsn(options, "http://public@127.0.0.1:9/1");
    sentry_options_set_release(options, "local-sandbox-service@smoke");
    sentry_options_set_environment(options, "windows-smoke");
    sentry_options_set_database_pathw(options, database);
    sentry_options_set_handler_pathw(options, handler);
    sentry_options_set_traces_sample_rate(options, 1.0);
    sentry_options_add_attachmentw(options, attachment);
    if (local_transport) {
        sentry_options_set_transport(
            options, sentry_transport_new(write_envelope));
    }
    return sentry_init(options);
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 6 || (wcscmp(argv[1], L"capture") != 0
                         && wcscmp(argv[1], L"crash") != 0
                         && wcscmp(argv[1], L"handler-loss") != 0)) {
        fwprintf(stderr,
            L"usage: lsb-sentry-smoke <capture|crash|handler-loss> <db> <handler> "
            L"<attachment> <envelope>\n");
        return 2;
    }

    const int capture = wcscmp(argv[1], L"crash") != 0;
    if (capture) {
        if (_wfopen_s(&envelope_file, argv[5], L"wb") != 0) {
            return 3;
        }
    }
    if (configure(argv[2], argv[3], argv[4], capture) != 0) {
        return 4;
    }

    sentry_set_tag("component", "local-sandbox-service");
    sentry_set_extra(
        "correlation_id", sentry_value_new_string("smoke-correlation"));
    if (!capture) {
        abort();
    }
    if (wcscmp(argv[1], L"handler-loss") == 0) {
        Sleep(5000);
    }

    sentry_capture_event(sentry_value_new_message_event(
        SENTRY_LEVEL_ERROR, "lsb-smoke", "representative sandbox failure"));
    sentry_transaction_context_t *context
        = sentry_transaction_context_new("sandbox.start", "sandbox.start");
    sentry_transaction_t *transaction
        = sentry_transaction_start(context, sentry_value_new_object());
    sentry_transaction_set_tag(
        transaction, "component", "local-sandbox-service");
    sentry_transaction_set_data(transaction, "correlation_id",
        sentry_value_new_string("smoke-correlation"));
    sentry_span_t *span = sentry_transaction_start_child(
        transaction, "sandbox.preflight", "preflight");
    sentry_span_set_status(span, SENTRY_SPAN_STATUS_OK);
    sentry_span_finish(span);
    sentry_transaction_set_status(transaction, SENTRY_SPAN_STATUS_OK);
    sentry_transaction_finish(transaction);
    sentry_close();
    fclose(envelope_file);
    return 0;
}
