# read data from data vault
# last update: 2018-01-07

options(warn=-1)

# get data from STDIN ====
myStdin <- file("stdin")
input <- suppressWarnings(readLines(myStdin))
close(myStdin)
inputParsed <- jsonlite::fromJSON(input)

# validation ====
if('pia_url' %in% names(inputParsed)){
        pia_url <- inputParsed$pia_url 
} else {
        stop('invalid format: attribute "pia_url" missing')
}

if('app_key' %in% names(inputParsed)){
        app_key <- inputParsed$app_key 
} else {
        stop('invalid format: attribute "app_key" missing')
}

if('app_secret' %in% names(inputParsed)){
        app_secret <- inputParsed$app_secret 
} else {
        stop('invalid format: attribute "app_secret" missing')
}

if('repo' %in% names(inputParsed)){
        repo <- inputParsed$repo 
} else {
        stop('invalid format: attribute "repo" missing')
}

keyItems <- ''
if('private_key' %in% names(inputParsed)){
        private_key <- inputParsed$private_key 
        keyItems <- data.frame(
                repo = as.character(repo),
                key  = as.character(private_key),
                read = TRUE,
                stringsAsFactors = FALSE
        )
} else if('password' %in% names(inputParsed)){
        app <- oydapp::setupApp(pia_url, app_key, app_secret, "")
        privateKey <- oydapp::getPrivatekey(app, inputParsed$password)
        privateKeyRaw <- sodium::sha256(charToRaw(privateKey))
        keyItems <- data.frame(
                repo = as.character(repo),
                key  = oydapp::raw2str(privateKeyRaw),
                read = TRUE,
                stringsAsFactors = FALSE
        )
}

# connect to data vault ====
app <- oydapp::setupApp(pia_url, app_key, app_secret, keyItems)

# read items from data vault ====
items <- oydapp::readItems(app, oydapp::itemsUrl(app$url, repo))

# write output ====
cat(jsonlite::toJSON(items))
