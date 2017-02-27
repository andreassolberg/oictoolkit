#! /bin/bash

# Run metadata-import linked to the docker-compose cassandra instance.
export RUN_PATH=`dirname "$0" || echo .`
set -a
. ${RUN_PATH}/_config.sh
set +a

docker stop ${KUBERNETES_DEPLOYMENT}
docker rm ${KUBERNETES_DEPLOYMENT}
docker run -d --name ${KUBERNETES_DEPLOYMENT} \
    -p 8080:8080 \
    -v ${PWD}/index.js:/app/index.js \
    -v ${PWD}/lib:/app/lib \
    -v ${PWD}/public:/app/public \
    -v ${PWD}/etc:/app/etc \
    -v ${PWD}/views:/app/views \
    -v /Users/andreas/wc/passport-dataporten:/app/node_modules/passport-dataporten \
    --env-file ENV ${IMAGE}
docker logs -f ${KUBERNETES_DEPLOYMENT}


# -v ${PWD}/etc/simplesamlphp-config:/feide/vendor/simplesamlphp/simplesamlphp/config \
# -v ${PWD}/etc/simplesamlphp-metadata:/feide/vendor/simplesamlphp/simplesamlphp/metadata \
#     -v ${PWD}/metadata-import/getmetadata.php:/metadata-import/getmetadata.php \
