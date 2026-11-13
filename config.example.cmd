@echo off
rem Copy this file to `config.cmd` and fill in your camera's details.
rem `config.cmd` is gitignored - your credentials never get committed.

rem The number printed on the camera / shown in the app.
rem NOTE: on this camera family the device id is ALSO the username. `admin` does not work.
set "DEVICE_ID=12345678"

rem The password you set for the camera in the V380 app.
rem Avoid cmd metacharacters (`^` `&` `|` `<` `>` `"` `%`) in the password, or quoting breaks.
set "PASSWORD=changeme"

rem Optional but recommended: the camera's MAC address.
rem Used to re-find the camera by hardware address when its DHCP lease changes.
rem Find it with:  arp -a   (look for the camera's IP; `aa-bb-cc-dd-ee-ff` and
rem `aa:bb:cc:dd:ee:ff` formats both work)
set "MAC=aa-bb-cc-dd-ee-ff"

rem Port the local MJPEG server listens on.
set "HTTP_PORT=8090"
