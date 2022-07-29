
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_sntp.h"
#include "esp_log.h"

/* This is mbedtls boilerplate for library configuration */
#include "mbedtls/config.h"

#include "cryptoauthlib.h"
#include "mbedtls/atca_mbedtls_wrap.h"

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

// generate csr
#include "mbedtls/x509_csr.h"
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"

static const char *TAG = "ATECC608A";

/* globals for mbedtls RNG */
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static int atca_generate_csr(void)
{

    mbedtls_pk_context pkey;
    int ret;

    unsigned char csr_out[1024];
    const char *common_name = "m5stackcore2foraws";

#ifdef MBEDTLS_ECDSA_SIGN_ALT
    /* Convert to an mbedtls key */
    ESP_LOGI(TAG, " Using a hardware private key ...");
    ret = atca_mbedtls_pk_init(&pkey, 0);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed !  atca_mbedtls_pk_init returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
#else
    ESP_LOGI(TAG, " Generating a software private key ...");
    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_setup(&pkey,
                           mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA));
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed !  mbedtls_pk_setup returned -0x%04x", -ret);
        goto exit;
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(pkey),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed !  mbedtls_ecp_gen_key returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
#endif

    const char *pers = "gen_csr";
    mbedtls_x509write_csr csr;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    /* Generating CSR from the private key */
    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "Seeding the random number generator.");
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04x", -ret);
        goto exit;
    }

    char subject_name[50];
    snprintf(subject_name, sizeof(subject_name), "CN=%s", common_name);
    ret = mbedtls_x509write_csr_set_subject_name(&csr, subject_name);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509write_csr_set_subject_name returned %d", ret);
        goto exit;
    }

    memset(csr_out, 0, sizeof(csr_out));
    mbedtls_x509write_csr_set_key(&csr, &pkey);

    ESP_LOGI(TAG, "Generating PEM");
    ret = mbedtls_x509write_csr_pem(&csr, csr_out, sizeof(csr_out), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509write_csr_pem returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "CSR generated.");
    ESP_LOGI(TAG, "Modified CSR : \n%s", csr_out);
exit:

    mbedtls_x509write_csr_free(&csr);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

static int configure_mbedtls_rng(void)
{
    int ret;
    const char *seed = "some random seed string";
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)seed, strlen(seed));
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed  ! mbedtls_ctr_drbg_seed returned %d", ret);
    }
    else
    {
        ESP_LOGI(TAG, " ok");
    }
    return ret;
}

static void close_mbedtls_rng(void)
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

/* An example hash */
static unsigned char hash[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static const uint8_t public_key_x509_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

static void print_public_key(uint8_t *pubkey)
{
    uint8_t buf[128];
    uint8_t *tmp;
    size_t buf_len = sizeof(buf);

    /* Calculate where the raw data will fit into the buffer */
    tmp = buf + sizeof(buf) - ATCA_PUB_KEY_SIZE - sizeof(public_key_x509_header);

    /* Copy the header */
    memcpy(tmp, public_key_x509_header, sizeof(public_key_x509_header));

    /* Copy the key bytes */
    memcpy(tmp + sizeof(public_key_x509_header), pubkey, ATCA_PUB_KEY_SIZE);

    /* Convert to base 64 */
    (void)atcab_base64encode(tmp, ATCA_PUB_KEY_SIZE + sizeof(public_key_x509_header), (char *)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = '\0';

    /* Print out the key */
    ESP_LOGI(TAG, "\r\n-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----", buf);
}

void atecc608init(void)
{
    int ret = 0;
    bool lock;
    uint8_t buf[ATCA_ECC_CONFIG_SIZE];
    uint8_t pubkey[ATCA_PUB_KEY_SIZE];

    /* Initialize the mbedtls library */
    ret = configure_mbedtls_rng();
#ifdef CONFIG_ATECC608A_TNG
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for Trust & GO ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6A;
#elif CONFIG_ATECC608A_TFLEX   /* CONFIG_ATECC608A_TNGO */
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for TrustFlex ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6C;
#elif CONFIG_ATECC608A_TCUSTOM /* CONFIG_ATECC608A_TFLEX */
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for TrustCustom ...");
    /* Default slave address is same as that of TCUSTOM ATECC608A chips */
#endif                         /* CONFIG_ATECC608A_TCUSTOM */
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed ! atcab_init returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");

    lock = 0;
    ESP_LOGI(TAG, " Check the data zone lock status...");
    ret = atcab_is_locked(LOCK_ZONE_DATA, &lock);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed\n  ! atcab_is_locked returned %02x", ret);
        goto exit;
    }

    if (lock)
    {
        ESP_LOGI(TAG, " ok: locked");
    }
    else
    {
        ESP_LOGE(TAG, "unlocked, please lock(configure) the ATECC608A chip with help of esp_cryptoauth_utility and try again");
        goto exit;
    }

    ESP_LOGI(TAG, " Get the device info (type)...");
    ret = atcab_info(buf);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed\n  ! atcab_info returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok: %02x %02x", buf[2], buf[3]);

    ESP_LOGI(TAG, " Get the public key...");
    ret = atcab_get_pubkey(0, pubkey);
    if (ret != 0)
    {
        ESP_LOGI(TAG, " failed\n  ! atcab_get_pubkey returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
    print_public_key(pubkey);

    ret = atca_generate_csr();
    if (ret != 0)
    {
        ESP_LOGE(TAG, " Generate CSR failed");
        goto exit;
    }

exit:
    fflush(stdout);
    close_mbedtls_rng();
}