# SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Compatibility wrapper for non-flake users.
# Prefer `nix develop` if you have flakes enabled.
(builtins.getFlake (toString ./.)).devShells.${builtins.currentSystem}.default
