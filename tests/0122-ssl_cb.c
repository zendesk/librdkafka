/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test.h"


struct test_context {
    char *ca_cert_pem;
    size_t ca_cert_pem_length;

    char *direct_signed_client_cert_pem;
    size_t direct_signed_client_cert_pem_length;
    char *direct_signed_client_key_pem;
    size_t direct_signed_client_key_pem_length;

    char *self_signed_client_cert_pem;
    size_t self_signed_client_cert_pem_length;
    char *self_signed_client_key_pem;
    size_t self_signed_client_key_pem_length;

    char *intermediate_signed_client_cert_pem;
    size_t intermediate_signed_client_cert_pem_length;
    char *intermediate_signed_client_key_pem;
    size_t intermediate_signed_client_key_pem_length;
    char *intermediate_signed_intermediate_cert_pem;
    size_t intermediate_signed_intermediate_cert_pem_length;
    char *intermediate_signed_intermediate_key_pem;
    size_t intermediate_signed_intermediate_key_pem_length;
};

static int ssl_client_cert_cb_good_direct(
        rd_kafka_t *rk,
        const char *broker_name,
        int32_t broker_id,
        char *buf, size_t *buf_size,
        char **leaf_cert, size_t *leaf_cert_size,
        char **pkey, size_t *pkey_size,
        char *chain_certs[16], size_t chain_cert_sizes[16],
        rd_kafka_cert_enc_t *format,
        void *opaque
) {
    struct test_context *ctx;
    size_t total_cert_len;

    ctx = (struct test_context*)opaque;
    total_cert_len = ctx->direct_signed_client_cert_pem_length + ctx->direct_signed_client_key_pem_length;
    if (*buf_size < total_cert_len) {
        *buf_size = total_cert_len;
        return RD_KAFKA_CERT_FETCH_MORE_BUFFER;
    }

    // copy cert, then key
    *leaf_cert = buf;
    *leaf_cert_size = ctx->direct_signed_client_cert_pem_length;
    *pkey = buf + ctx->direct_signed_client_cert_pem_length;
    *pkey_size = ctx->direct_signed_client_key_pem_length;
    *format = RD_KAFKA_CERT_ENC_PEM;
    memcpy(*leaf_cert, ctx->direct_signed_client_cert_pem, ctx->direct_signed_client_cert_pem_length);
    memcpy(*pkey, ctx->direct_signed_client_key_pem, ctx->direct_signed_client_key_pem_length);
    return RD_KAFKA_CERT_FETCH_OK;
}

static int ssl_client_cert_cb_bad(
        rd_kafka_t *rk,
        const char *broker_name,
        int32_t broker_id,
        char *buf, size_t *buf_size,
        char **leaf_cert, size_t *leaf_cert_size,
        char **pkey, size_t *pkey_size,
        char *chain_certs[16], size_t chain_cert_sizes[16],
        rd_kafka_cert_enc_t *format,
        void *opaque
) {
    struct test_context *ctx;
    size_t total_cert_len;

    ctx = (struct test_context*)opaque;
    total_cert_len = ctx->direct_signed_client_cert_pem_length + ctx->direct_signed_client_key_pem_length;
    if (*buf_size < total_cert_len) {
        *buf_size = total_cert_len;
        return RD_KAFKA_CERT_FETCH_MORE_BUFFER;
    }

    // copy cert, then key
    *leaf_cert = buf;
    *leaf_cert_size = ctx->self_signed_client_cert_pem_length;
    *pkey = buf + ctx->self_signed_client_cert_pem_length;
    *pkey_size = ctx->self_signed_client_key_pem_length;
    *format = RD_KAFKA_CERT_ENC_PEM;
    memcpy(*leaf_cert, ctx->self_signed_client_cert_pem, ctx->self_signed_client_cert_pem_length);
    memcpy(*pkey, ctx->self_signed_client_key_pem, ctx->self_signed_client_key_pem_length);
    return RD_KAFKA_CERT_FETCH_OK;
}

static int ssl_client_cert_cb_good_via_intermediate(
        rd_kafka_t *rk,
        const char *broker_name,
        int32_t broker_id,
        char *buf, size_t *buf_size,
        char **leaf_cert, size_t *leaf_cert_size,
        char **pkey, size_t *pkey_size,
        char *chain_certs[16], size_t chain_cert_sizes[16],
        rd_kafka_cert_enc_t *format,
        void *opaque
) {
    struct test_context *ctx;
    size_t total_cert_len;

    ctx = (struct test_context*)opaque;
    total_cert_len = ctx->intermediate_signed_client_cert_pem_length +
                     ctx->intermediate_signed_client_key_pem_length +
                     ctx->intermediate_signed_intermediate_cert_pem_length;
    if (*buf_size < total_cert_len) {
        *buf_size = total_cert_len;
        return RD_KAFKA_CERT_FETCH_MORE_BUFFER;
    }

    // copy cert, then key
    *leaf_cert = buf;
    *leaf_cert_size = ctx->intermediate_signed_client_cert_pem_length;
    *pkey = buf + ctx->intermediate_signed_client_cert_pem_length;
    *pkey_size = ctx->intermediate_signed_client_key_pem_length;
    chain_certs[0] = *pkey + ctx->intermediate_signed_client_key_pem_length;
    chain_cert_sizes[0] = ctx->intermediate_signed_intermediate_cert_pem_length;
    *format = RD_KAFKA_CERT_ENC_PEM;
    memcpy(*leaf_cert, ctx->intermediate_signed_client_cert_pem, ctx->intermediate_signed_client_cert_pem_length);
    memcpy(*pkey, ctx->intermediate_signed_client_key_pem, ctx->intermediate_signed_client_key_pem_length);
    memcpy(chain_certs[0], ctx->intermediate_signed_intermediate_cert_pem, ctx->intermediate_signed_intermediate_cert_pem_length);
    return RD_KAFKA_CERT_FETCH_OK;
}


typedef int (*ssl_cert_fetch_cb) (rd_kafka_t *rk,
                                  const char *broker_name,
                                  int32_t broker_id,
                                  char *buf, size_t *buf_size,
                                  char **leaf_cert, size_t *leaf_cert_size,
                                  char **pkey, size_t *pkey_size,
                                  char *chain_certs[16], size_t chain_cert_sizes[16],
                                  rd_kafka_cert_enc_t *format,
                                  void *opaque);

static void do_test_ssl_cb(struct test_context *ctx, int expect_ok, ssl_cert_fetch_cb cb) {
    // Test needs to.....
    // ....construct a rdkafka config with a SSL CB that returns a GOOD cert
    // ....make a metadata request of some kind

    rd_kafka_t *rk;
    rd_kafka_conf_t *conf;
    const rd_kafka_metadata_t *md;
    rd_kafka_resp_err_t md_res;
    char errstr[512];

    test_conf_init(&conf, NULL, 10000);
    rd_kafka_conf_set_ssl_cert_fetch_cb(conf, cb);
    rd_kafka_conf_set_opaque(conf, ctx);

    rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!rk) {
        rd_kafka_conf_destroy(conf);
        TEST_FAIL_LATER("failed rd_kafka_new: %s\n", errstr);
        return;
    }

    md_res = rd_kafka_metadata(rk, 1, NULL, &md, 4000);
    if (md_res != RD_KAFKA_RESP_ERR_NO_ERROR) {
        rd_kafka_destroy(rk);
        if (expect_ok) {
            TEST_FAIL_LATER("failed rd_kafka_metadata: %s\n", rd_kafka_err2str(md_res));
        }
        return;
    }
    if (!expect_ok) {
        TEST_FAIL_LATER("passed rd_kafka_metadata, but expected to fail\n");
    }
    rd_kafka_metadata_destroy(md);
    rd_kafka_destroy(rk);
    return;
}


static void read_ssl_file_from_env(const char *envvar, char **dest, size_t *length) {
    const char *path_val;
    size_t szrt;
    FILE *fh;

    path_val = test_getenv(envvar, NULL);
    if (!path_val) {
        TEST_SKIP("Test requires %s env var\n", envvar);
        return;
    }
    fh = fopen(path_val, "rb");
    if (!fh) {
        TEST_FAIL_LATER("File %s could not be opened: %m\n", path_val);
        return;
    }
    fseek(fh, 0, SEEK_END);
    *length = ftell(fh);
    fseek(fh, 0, SEEK_SET);

    *dest = malloc(*length);
    // should probably handle short reads, but *shrug*
    szrt = fread(*dest, 1, *length, fh);
    if (!szrt) {
        TEST_FAIL_LATER("File %s could not be read: %m\n", path_val);
        fclose(fh);
        return;
    }
    fclose(fh);
    return;
}

int main_0122_ssl_cb(int argc, char **argv) {
    struct test_context ctx;

    memset(&ctx, 0, sizeof(struct test_context));

    if (!test_check_builtin("ssl")) {
        TEST_SKIP("Test requires SSL support\n");
        goto cleanup;
    }
    if (!test_check_builtin("ssl_client_cert_callback")) {
        TEST_SKIP("Test requires ssl_client_cert_callback support (i.e. built with openssl >= 1.0.2\n");
        goto cleanup;
    }


    read_ssl_file_from_env(
            "RDK_SSL_ca_pem", &ctx.ca_cert_pem, &ctx.ca_cert_pem_length
    );
    read_ssl_file_from_env(
            "RDK_SSL_pub_pem", &ctx.direct_signed_client_cert_pem, &ctx.direct_signed_client_cert_pem_length
    );
    read_ssl_file_from_env(
            "RDK_SSL_priv_pem", &ctx.direct_signed_client_key_pem, &ctx.direct_signed_client_key_pem_length
    );
    read_ssl_file_from_env(
            "RDK_UNTRUSTEDSSL_pub_pem", &ctx.self_signed_client_cert_pem, &ctx.self_signed_client_cert_pem_length
    );
    read_ssl_file_from_env(
            "RDK_UNTRUSTEDSSL_priv_pem", &ctx.self_signed_client_key_pem, &ctx.self_signed_client_key_pem_length
    );
    read_ssl_file_from_env(
            "RDK_INTERMEDIATESSL_pub_pem", &ctx.intermediate_signed_client_cert_pem, &ctx.intermediate_signed_client_cert_pem_length
    );
    read_ssl_file_from_env(
            "RDK_INTERMEDIATESSL_priv_pem", &ctx.intermediate_signed_client_key_pem, &ctx.intermediate_signed_client_key_pem_length
    );
    read_ssl_file_from_env(
            "RDK_INTERMEDIATESSL_intermediate_pub_pem", &ctx.intermediate_signed_intermediate_cert_pem, &ctx.intermediate_signed_intermediate_cert_pem_length
    );
    read_ssl_file_from_env(
            "RDK_INTERMEDIATESSL_intermediate_priv_pem", &ctx.intermediate_signed_intermediate_key_pem, &ctx.intermediate_signed_intermediate_key_pem_length
    );
    if (test_curr->state == TEST_SKIPPED || test_curr->state == TEST_FAILED) {
        goto cleanup;
    }

    do_test_ssl_cb(&ctx, 1, ssl_client_cert_cb_good_direct);
    if (test_curr->state == TEST_SKIPPED || test_curr->state == TEST_FAILED) {
        goto cleanup;
    }
    do_test_ssl_cb(&ctx, 1, ssl_client_cert_cb_good_via_intermediate);
    if (test_curr->state == TEST_SKIPPED || test_curr->state == TEST_FAILED) {
        goto cleanup;
    }
    do_test_ssl_cb(&ctx, 0, ssl_client_cert_cb_bad);
    if (test_curr->state == TEST_SKIPPED || test_curr->state == TEST_FAILED) {
        goto cleanup;
    }

    cleanup:
        free(ctx.ca_cert_pem);
        free(ctx.direct_signed_client_cert_pem);
        free(ctx.direct_signed_client_key_pem);
        free(ctx.self_signed_client_cert_pem);
        free(ctx.self_signed_client_key_pem);
        free(ctx.intermediate_signed_client_cert_pem);
        free(ctx.intermediate_signed_client_key_pem);
        free(ctx.intermediate_signed_intermediate_cert_pem);
        free(ctx.intermediate_signed_intermediate_key_pem);
        return (test_curr->state == TEST_FAILED ? 1 : 0);
}
