#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
# SPDX-License-Identifier: GPL-3.0-or-later

import cv2


def main():
    video = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()

    last_item = None
    while True:
        ret, frame = video.read()
        if not ret:
            print('Error: no frame grabbed')
            break

        ret, data, points, _ = detector.detectAndDecodeMulti(frame)

        if ret:
            frame = cv2.polylines(frame, points.astype(int), True, (0, 255, 0), 3)
            for item in data:
                if item == '':
                    continue

                if item != last_item:
                    print(item)
                    last_item = item

        cv2.imshow('Video capture', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()


if __name__ == '__main__':
    main()
