FROM rocker/r-base
MAINTAINER "Christoph Fabianek" christoph@ownyourdata.eu

RUN apt-get update \
        && apt-get install -y --no-install-recommends \
                libcurl4-openssl-dev \
                libssl-dev \
                libssh2-1-dev \
                libxml2-dev \
                libsodium-dev \
        && rm -rf /var/lib/apt/lists/* \
        && R -e "install.packages(c( \
                'devtools', \
                'jsonlite', \
                'RCurl', \
                'data.table', \
                'sodium', \
                'dplyr', \
                'shiny'), repos='http://cran.r-project.org')" \
        && R -e "devtools::install_github('ownyourdata/oydapp')" \
	&& mkdir -p /srv-pia_read

USER docker

COPY script/run.sh /bin/run.sh
COPY script/*.R /srv-pia_read/

CMD ["/bin/bash"]
