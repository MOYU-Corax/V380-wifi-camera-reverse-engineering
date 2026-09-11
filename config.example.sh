# Copy this file to `config.sh` and fill in your camera's details.
# `config.sh` is gitignored — your credentials never get committed.

# The number printed on the camera / shown in the app.
# NOTE: on this camera family the device id is ALSO the username. `admin` does not work.
DEVICE_ID=12345678

# The password you set for the camera in the V380 app.
PASSWORD='changeme'

# Optional but recommended: the camera's MAC address.
# Used to re-find the camera by hardware address when its DHCP lease changes.
# Find it with:  ip neigh | grep <camera-ip>
MAC=aa:bb:cc:dd:ee:ff

# Port the local MJPEG server listens on.
HTTP_PORT=8090
