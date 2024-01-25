#pragma once
#include <ios>
#include <sstream>

struct MessageHandler {
  std::stringstream parms_stream;
  std::stringstream data_stream;
  std::stringstream sk_stream;
  std::streamoff last_write_size;
};