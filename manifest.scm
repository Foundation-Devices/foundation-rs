;;; SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
;;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Manifest used to set up a development environment.
;;;
;;; guix shell

(specifications->manifest
  '("cmake"
    "gcc-toolchain"
    "guile"
    "jq"
    "make"
    "nlohmann-json"
    "reuse"
    "rust"
    "rust:cargo"
    "rust:tools"

    ;; Nice to have utilities.
    "hal"
    "xxd"))
