# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

set(COMPONENT_INCLUDE_DIRS
    .
    ../config
    ./includes
)

idf_component_register(SRCS azure_iot_freertos_esp32_main.c atecc608.c
                    INCLUDE_DIRS ${COMPONENT_INCLUDE_DIRS}
                    REQUIRES freertos nvs_flash coreMQTT azure-sdk-for-c azure-iot-middleware-freertos sample-azure-iot)

