// Copyright (c) 2017 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_PORT_PORT_CONFIG_H_
#define STORAGE_LEVELDB_PORT_PORT_CONFIG_H_

// Define to 1 if you have a definition for fdatasync() in <unistd.h>.
#if defined(_WIN32)
#define HAVE_FDATASYNC 0
#define HAVE_FULLFSYNC 0
#define HAVE_O_CLOEXEC 0
#elif defined(__linux__)
#define HAVE_FDATASYNC 1
#define HAVE_FULLFSYNC 0
#define HAVE_O_CLOEXEC 1
#elif defined(__APPLE__)
#define HAVE_FDATASYNC 0
#define HAVE_FULLFSYNC 1
#define HAVE_O_CLOEXEC 1
#else
#define HAVE_FDATASYNC 0
#define HAVE_FULLFSYNC 0
#define HAVE_O_CLOEXEC 1
#endif

// Define to 1 if you have Google CRC32C.
#define HAVE_CRC32C 0

// Define to 1 if you have Google Snappy.
#define HAVE_SNAPPY 1

#endif  // STORAGE_LEVELDB_PORT_PORT_CONFIG_H_
