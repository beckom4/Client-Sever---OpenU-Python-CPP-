#pragma once

#include <iostream>
#include <cstdint>
#include <iomanip>
#include <string>
#include <cstdint>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/read.hpp>

#include "FileHandler.cpp"
#include "checksum.cpp"


#define REGISTRATION 1025
#define SEND_PUBLIC_KEY 1026
#define RE_REG 1027
#define SEND_FILE 1028
#define VALID_CRC 1029
#define INVALID_CRC 1030
#define INVALID_CRC_FINAL 1031

// Response codes
#define REG_SUCCESS 2100
#define REG_FAILED 2101
#define AES_ISSUED 2102
#define FILE_RECEIVED 2103
#define GENERAL_APPROVAL 2104
#define REG_AGAIN_APPROVED 2105
#define REG_AGAIN_FAILED 2106
#define GENERAL_ERROR 2107

#define INT_SIZE 4
#define HEADER_SIZE 7
#define ID_SIZE 16
#define NAME_SIZE 255
#define REG_SIZE 23
#define GENERAL_APPROVAL_SIZE 23
#define PUB_KEY_SIZE 160
#define PUB_KEY_PAYLOAD_SIZE 415
#define FILE_RESPONSE_SIZE 286
#define CLIENT_VERSION '3'
