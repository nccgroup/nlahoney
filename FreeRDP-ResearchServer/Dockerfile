FROM ubuntu
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
	autotools-dev \
	build-essential \
	cdbs \
	cmake \
	debhelper \
	docbook-xsl \
	dpkg-dev \
	git-core \
	libasound2-dev \
	libavcodec-dev \
	libavresample-dev \
	libavutil-dev \
	libcups2-dev \
	libdbus-glib-1-dev \
	libfaac-dev \
	libfaad-dev \
	libgsm1-dev \
	libgstreamer-plugins-base1.0-dev \
	libgstreamer1.0-dev \
	libjpeg-dev \
	libpcsclite-dev \
	libpulse-dev \
	libssl-dev \
	libudev-dev \
	libusb-1.0-0-dev \
	libwayland-dev \
	libx11-dev \
	libxcursor-dev \
	libxdamage-dev \
	libxext-dev \
	libxfixes-dev \
	libxi-dev \
	libxinerama-dev \
	libxkbfile-dev \
	libxml2-dev \
	libxrandr-dev \
	libxrender-dev \
	libxtst-dev \
	libxv-dev \
	ninja-build \
	pkg-config \
	uuid-dev \
	xmlto \
	xsltproc \
	xvfb

COPY . /FreeRDP
WORKDIR /build
RUN cmake -DWITH_SERVER=ON /FreeRDP
RUN cmake --build .
