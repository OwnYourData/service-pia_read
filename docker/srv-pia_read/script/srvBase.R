# basic functions for accessing PIA
# last update: 2017-09-18

oydLog <- function(msg)
        cat(paste(Sys.time(), msg, "\n"))
# oydLog(capture.output(pryr::where("variable")))

# Low-level functions to access PIA =======================
# used header for GET and POST requests
defaultHeaders <- function(token) {
        c('Accept'        = '*/*',
          'Content-Type'  = 'application/json',
          'Authorization' = paste('Bearer', token))
}

# URL to access a repo
itemsUrl <- function(url, repo_name) {
        paste0(url, '/api/repos/', repo_name, '/items')
}

# extract URL from repo URL
repoFromUrl <- function(url) {
        sub(".*?/api/repos/(.*?)/items", "\\1", url, perl = TRUE)
}

# request token for a plugin (app)
getToken <- function(pia_url, app_key, app_secret) {
        auth_url <- paste0(pia_url, '/oauth/token')
        # reduce response timeout to 10s to avoid hanging app
        # https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html
        optTimeout <- RCurl::curlOptions(connecttimeout = 10)
        response <- tryCatch(
                RCurl::postForm(auth_url,
                                client_id     = app_key,
                                client_secret = app_secret,
                                grant_type    = 'client_credentials',
                                .opts         = optTimeout),
                error = function(e) { return(NA) })
        if (is.na(response)) {
                return(NA)
        } else {
                if(jsonlite::validate(response[1])){
                        return(jsonlite::fromJSON(response[1])$access_token)
                } else {
                        return(NA)
                }
        }
}

# vector with all plugin (app) infos to access PIA
setupApp <- function(pia_url, app_key, app_secret, keyItems) {
        app_token <- getToken(pia_url,
                              app_key,
                              app_secret)
        if(is.na(app_token)){
                list()
        } else {
                list('url'        = pia_url,
                     'app_key'    = app_key,
                     'app_secret' = app_secret,
                     'token'      = app_token,
                     'encryption' = keyItems)
        }
}

# Read and CRUD Operations for a Plugin (App) =============
# convert response string into data.frame
r2d <- function(response){
        if (is.na(response)) {
                data.frame()
        } else {
                if (nchar(response) > 0) {
                        retVal <- jsonlite::fromJSON(response)
                        if(length(retVal) == 0) {
                                data.frame()
                        } else {
                                if ('error' %in% names(retVal)) {
                                        data.frame()
                                } else {
                                        if ('message' %in% names(retVal)) {
                                                if (retVal$message ==
                                                    'error.accessDenied') {
                                                        data.frame()
                                                } else {
                                                        # convert list to data.frame
                                                        tmp <- jsonlite::fromJSON(response)
                                                        if(typeof(tmp) == 'character'){
                                                                tmp <- lapply(tmp, jsonlite::fromJSON)
                                                        }
                                                        if(typeof(tmp) == 'list'){
                                                                data.table::rbindlist(tmp, fill=TRUE)
                                                        } else {
                                                                tmp
                                                        }
                                                }
                                        } else {
                                                # convert list to data.frame
                                                tmp <- jsonlite::fromJSON(response)
                                                if(typeof(tmp) == 'character'){
                                                        tmp <- lapply(tmp, jsonlite::fromJSON)
                                                }
                                                if(typeof(tmp) == 'list'){
                                                        data.table::rbindlist(tmp, fill=TRUE)
                                                } else {
                                                        tmp
                                                }
                                        }
                                }
                        }
                } else {
                        data.frame()
                }
        }
}

oydDecrypt <- function(app, repo_url, data){
        privateKey <- getReadKey(app$encryption,
                                 repoFromUrl(repo_url))
        errorMsg <- ''
        warningMsg <- ''
        retVal <- data.frame()

        if(length(privateKey) == 1){
                testJSON <- as.character(data[1, 'value'])
                if(jsonlite::validate(testJSON)){
                        data$json <- as.character(data$value)
                } else {
                        errorMsg <- 'msgMissingKey'
                }
        } else {
                if(anyNA(data$nonce)){
                        data$json <- as.character(data$value)
                        warningMsg <- 'msgUnencryptedDataWithKey'
                } else {
                        authKey <- sodium::pubkey(
                                sodium::sha256(charToRaw('auth')))
                        decryptError <- FALSE
                        data$json <- tryCatch(
                                apply(data, 1, function(x) {
                                        cipher <- str2raw(as.character(
                                                x['value']))
                                        nonce <- str2raw(as.character(
                                                x['nonce']))
                                        rawToChar(sodium::auth_decrypt(
                                                cipher,
                                                privateKey,
                                                authKey,
                                                nonce))
                                }),
                                error = function(e) {
                                        decryptError <<- TRUE
                                        return(NA) })
                        if(decryptError){
                                errorMsg <- 'msgDecryptError'
                        }
                }
        }
        if(nchar(errorMsg) == 0){
                parseError <- FALSE
                retVal <- tryCatch(
                        do.call(rbind.data.frame,
                                lapply(data$json,
                                       function(x) jsonlite::fromJSON(x))),
                        error = function(e) {
                                parseError <<- TRUE
                                return(data.frame()) })
                if(parseError){
                        errorMsg <- 'msgCantParseJSON'
                } else {
                        retVal$id <- data$id
                        retVal$created_at <- data$created_at
                }
        }
        if(nchar(errorMsg) > 0){
                attr(retVal, "error") <- errorMsg
        }
        if(nchar(warningMsg) > 0){
                attr(retVal, "warning") <- warningMsg
        }
        retVal
}

# read raw data from PIA
readRawItems <- function(app, repo_url) {
        page_size = 2000
        headers <- defaultHeaders(app$token)
        url_data <- paste0(repo_url, '?size=', page_size)
        header <- RCurl::basicHeaderGatherer()
        doc <- tryCatch(
                RCurl::getURI(url_data,
                              .opts=list(httpheader = headers),
                              headerfunction = header$update),
                error = function(e) { return(NA) })
        response <- NA
        respData <- data.frame()
        if(!is.na(doc)){
                if(header$value()[['status']] == '200'){
                        recs <- tryCatch(
                                as.integer(header$value()[['X-Total-Count']]),
                                error = function(e) { return(0) })
                        if(recs > page_size) {
                                page_count <- floor(recs/page_size)
#                                shiny::withProgress(
#                                        value = 0, {
                                                for(page in 1:(page_count+1)){
                                                        url_data <- paste0(
                                                                repo_url,
                                                                '?page=', page,
                                                                '&size=', page_size)
                                                        response <- tryCatch(
                                                                RCurl::getURL(
                                                                        url_data,
                                                                        .opts=list(httpheader=headers)),
                                                                error=function(e){ return(NA) })
                                                        subData <- r2d(response)
                                                        if(nrow(respData)>0){
                                                                respData <- data.table::rbindlist(list(respData, subData), fill=TRUE)
                                                        } else {
                                                                respData <- subData
                                                        }
#                                                        shiny::incProgress(1/page_count)
                                                }
#                                })
                        } else {
                                response <- tryCatch(
                                        RCurl::getURL(
                                                url_data,
                                                .opts=list(httpheader=headers)),
                                        error = function(e) { return(NA) })
                                respData <- r2d(response)
                        }
                } else {
                        if(is.null(jsonlite::fromJSON(doc)$statusMessage)){
                                if(is.null(jsonlite::fromJSON(doc)$error)){
                                        attr(respData, 'error') <-
                                                jsonlite::fromJSON(doc)$message
                                } else {
                                        attr(respData, 'error') <-
                                                jsonlite::fromJSON(doc)$error
                                }
                        } else {
                                attr(respData, 'error') <-
                                        jsonlite::fromJSON(doc)$statusMessage
                        }
                }
        }
        respData
}

# read data from PIA and decrypt if possible
readItems <- function(app, repo_url) {
        if (length(app) == 0) {
                data.frame()
                return()
        }
        respData <- readRawItems(app, repo_url)
        if(nrow(respData) > 0){
                if('version' %in% colnames(respData)){
                        if(respData[1, 'version'] == oydDataVersion){
                                oydDecrypt(app, repo_url, respData)
                        } else {
                                respData
                        }
                } else {
                        respData
                }
        } else {
                respData
        }
}

# transform item into OYD record format and call writeItem()
# OYD record format
#  - id: unique ID provided by PIA, if provided it is used for updates
#  - value: actual payload (encrypted)
#  - nonce: used for encryption
#  - version: currently v0.4
#  - crated_at: current timestamp
#
# later addtions may include:
#  - blockchain_reference
#  - owner: signed original payload
#
writeOydItem <- function(app, repo_url, item, id, addFields = list()){
        publicKey <- getWriteKey(app$encryption,
                                 repoFromUrl(repo_url))
        message <- jsonlite::toJSON(item, auto_unbox = TRUE)
        value <- message
        nonce <- ''
        if(length(publicKey) > 1){
                authKey <- sodium::sha256(charToRaw('auth'))
                nonce   <- sodium::random(24)
                cipher  <- sodium::auth_encrypt(charToRaw(message),
                                                authKey,
                                                publicKey,
                                                nonce)
                value   <- paste0(as.hexmode(as.integer(cipher)),
                                  collapse = '')
                nonce   <- paste0(as.hexmode(as.integer(nonce)),
                                  collapse = '')
        }
        oyd_item <- list(
                value      = value,
                version    = oydDataVersion
        )
        if(nzchar(nonce)){
                oyd_item <- c(oyd_item, c(nonce = nonce))
        }
        if(length(addFields) > 0){
                oyd_item <- c(oyd_item, addFields)
        }
        if(missing(id)){
                oyd_item <- c(oyd_item, c(created_at = getTsNow()))
                writeItem(app, repo_url, oyd_item)
        } else {
                # items <- readItems(app, repo_url)
                oyd_item <- c(oyd_item, c(id = as.numeric(id),
                                          update_at = getTsNow()))
                updateItem(app, repo_url, oyd_item, id)
        }

}

# write data into PIA
writeItem <- function(app, repo_url, item) {
        headers <- defaultHeaders(app$token)
        data <- jsonlite::toJSON(item, auto_unbox = TRUE)
        response <- tryCatch(
                httr::POST(repo_url,
                           body = data,
                           encode = 'json',
                           httr::add_headers(.headers = headers)),
                error = function(e) {
                        return(e) })
        if("status_code" %in% names(response)){
                if(response$status_code == 200){
                        httr::content(response)
                } else {
                        retVal <- ''
                        attr(retVal, 'error') <- response$status_code
                        retVal
                }
        } else {
                errrorMessage <- trimws(response$message)
                response <- ''
                attr(response, 'error') <- errrorMessage
                response
        }
}

# update record in PIA
updateItem <- function(app, repo_url, item, id) {
        headers <- defaultHeaders(app$token)
        data <- jsonlite::toJSON(item, auto_unbox = TRUE)
        url <- paste0(repo_url, '/', id)
        response <- tryCatch(
                httr::PUT(url,
                          body = data,
                          encode = 'json',
                          httr::add_headers(.headers = headers)),
                error = function(e) {
                        return(e) })
        if("status_code" %in% names(response)){
                if(response$status_code == 200){
                        httr::content(response)
                } else {
                        retVal <- ''
                        attr(retVal, 'error') <- response$status_code
                        retVal
                }
        } else {
                errrorMessage <- tryCatch(
                        errrorMessage <- trimws(response$message),
                        error = function(e){
                                return("no error info")
                        })
                retVal <- ''
                attr(retVal, 'error') <- errrorMessage
                retVal
        }
}

# delete data in PIA
deleteItem <- function(app, repo_url, id){
        headers <- defaultHeaders(app$token)
        item_url <- paste0(repo_url, '/', id)
        response <- tryCatch(
                httr::DELETE(item_url,
                             httr::add_headers(headers)),
                error = function(e) { return(NA) })
        if(!is.null(response$status_code)){
                response$status_code
        } else {
                'unknown'
        }
}

# delete all items in a repo
deleteRepo <- function(app, repo_url){
        allItems <- readItems(app, repo_url)
        lapply(allItems$id,
               function(x) deleteItem(app, repo_url, x))
}
