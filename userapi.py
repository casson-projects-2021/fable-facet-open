# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownParameterType=false
# pyright: reportMissingParameterType=false
# pyright: reportUnusedCallResult=false
# pyright: reportAny=false


import functions_framework
from flask import redirect

from google.auth.transport.requests import Request as GoogleRequestTransport
#from google.auth.transport.requests import AuthorizedSession
import googleapiclient.errors

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import google.auth
from googleapiclient.discovery import build
from google.cloud import bigquery

from google.cloud import bigquery_storage_v1
from google.cloud.bigquery_storage_v1 import types as bq_types
from google.protobuf import descriptor_pb2
import schema_pb2

from google.oauth2 import id_token
import io
import os
import requests
import time
import base64
from datetime import datetime, timezone
import json
import uuid

from google import genai
from google.genai import types as ai_types

from google.cloud import api_keys_v2
from google.cloud.api_keys_v2 import Key as API_Key

import httpx
import asyncio

from google.cloud.resourcemanager_v3 import ProjectsClient


TABLE_MAP = {
    "texts_index": schema_pb2.TextsIndex,
    "texts": schema_pb2.Texts
}

triangle = None

bq = None
bq_writer = None
ai_client = None

ai_prompt = ""


@functions_framework.http
def main( request ):
    global triangle, bq, ai_prompt, ai_client

    credentials, project_id = auth_data()

    # TODO: criar o log sink acionavel pela central:
    # Log query
    # (resource.type = "cloud_run_revision" OR resource.type = "cloud_function") ( httpRequest.status >= 300 OR severity >= ERROR OR (severity = DEFAULT AND ("Traceback" OR "Exception")) )
    # e enviar para o slack. O webhook deve ser enviado pela central tb

    ALLOWED_ORIGINS = {
        'https://cliente.fablefacet.com',
        'https://fablefacet.com'
    }

    origin = request.headers.get( 'Origin' )
    active_origin = origin if origin in ALLOWED_ORIGINS else None

    headers = {
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '600'
    }
    if active_origin:
        headers[ 'Access-Control-Allow-Origin' ] = active_origin
    else:
        host = request.args.get( 'h' )
        if host == "cli":
            headers[ 'Access-Control-Allow-Origin' ] = 'https://cliente.fablefacet.com'
        else:
            headers[ 'Access-Control-Allow-Origin' ] = 'https://fablefacet.com'

    if request.method == 'OPTIONS':
        return ( '', 204, headers )

    central_url = "https://api.fablefacet.com"

    tstamp = int( time.time())

    response_headers = {
        'Content-Type': 'text/html',
        'Access-Control-Allow-Origin': headers[ 'Access-Control-Allow-Origin' ]
    }

    # tab E only in requests using GET to validate tabs opened using window.open
    tab_id = request.args.get( 'tab' )

    if triangle is None:
        metakey, resp_err, triangle = get_triangle()
        triangle = triangle.replace( "https://fablefacet.com?triangle=", "" )

    # the only other request using GET is related to IAP
    if request.method == 'GET' and tab_id is None:
        task = request.args.get( 'task' )

        if task is None:
            return ( '', 404 )

        # encrypted
        task = decrypt_aes( task, triangle ).strip()

        if "running_window_maintenance::" in task:
            # no replay attacks
            remote_time = int( task[ task.find( "::" ) + 2 : ])
            print( "renovacao de IAP chamada " + str( tstamp ) + " " + str( remote_time ))

            # 120s here because offsets of more than 60s occurred (it should not be the case
            # since we are using Google's headers here to set the timers)
            if ( tstamp - remote_time ) > 120:
                return ( "", 404 )

            client_id = request.args.get( 'client_id' )
            oidc_token = id_token.fetch_id_token( GoogleRequestTransport() , audience = client_id )

            enc_res = encrypt_aes( oidc_token, triangle )
            print( response_headers )
            return ( enc_res, 200, response_headers )

        else:
            print( "renovacao de IAP INVALIDA" )


    # tab E only in requests using GET to validate tabs opened using window.open
    if request.method == 'GET' and tab_id is not None:
        prism = request.args.get( 'prism' )
        task = request.args.get( 'task' )
        host = request.args.get( 'h' )

        if prism is None:
            return ( f'<output>no prism - {tstamp}</output>', 200, response_headers )

        if host is None:
            return ( f'<output>cannot generate header - {tstamp}</output>', 200, response_headers )

        # login
        task = task.replace( ".", "=" )
        to_decrypt = task.encode( "utf-8" )
        iv_b64 = to_decrypt[ 0:16 ]
        iv = base64.urlsafe_b64decode( iv_b64 )

        to_decrypt = to_decrypt[ 16: ]
        to_decrypt_b = base64.urlsafe_b64decode( to_decrypt )

        aesgcm = AESGCM( base64.urlsafe_b64decode( triangle ))
        decrypted = aesgcm.decrypt( iv, to_decrypt_b, None )

        # encripted by the client (ff wasm) as proof of key's possession
        if decrypted.decode( 'utf-8' ) == "task_is_to_log_in_your_own_account":
            url = ""
            if host == "cli":
                url = "https://cliente.fablefacet.com"
            if host == "ff":
                url = "https://fablefacet.com"

            # inform the central API
            auth_jwt = request.headers.get( 'X-Goog-IAP-JWT-Assertion' )      # jwt token
            body = {
                "task": "user_login",
                "prism": prism,
                "user": auth_jwt,
                "h": host
            }
            headers = { "Content-Type": "application/x-www-form-urlencoded" }

            requests.post( central_url, data = body, headers = headers )

            enc_challenge = str( tstamp ) + "|" + tab_id
            enc_challenge = encrypt_aes( enc_challenge, triangle )

            return redirect( f"{url}/userAPI.html?bat=" + enc_challenge, code = 302 )
        else:
            return ( '', 404 )


    # all other calls must use POST
    #post = request.get_data( as_text = True )

    prism = request.form.get( 'prism' )
    task = request.form.get( 'task' )
    host = request.form.get( 'h' )

    # server-to-server call - FF api will call it. Don't call directly, don't modify it.
    # calling it with different values for the params other than the one the central API
    # holds will cause the userAPI to lost sync and Fable Facet site will stop editing texts

    if task == "relate":
        triangle = request.form.get( 'triangle' )  # sent url-safe from centralAPI

        # update the meta-key 
        metakey, resp_err, _ = get_triangle()

        if metakey is None:
            return resp_err

        key_name = metakey[ "name" ]

        body = {
            "restrictions": {
                "browserKeyRestrictions": {
                    "allowedReferrers": [
                        f"https://fablefacet.com?triangle={triangle}"
                    ]
                }
            }
        }

        try:
            service = build( 'apikeys', 'v2', credentials = credentials )

            _ = service.projects().locations().keys().patch(
                    name = key_name,
                    updateMask = "restrictions.browserKeyRestrictions",
                    body = body
                )
        except googleapiclient.errors.HttpError as err:
            print( "cannot change FF metakey, YFC can't run" )
            return ( "error=metakey_hard", 200 )

        # IAP tokens
        #auth_email = request.headers.get( 'X-Goog-Authenticated-User-Email' )  # accounts.google.com:email
        #auth_email = auth_email.replace( "accounts.google.com:", "" )

        #auth_user = request.headers.get( 'X-Goog-Authenticated-User-Id' )      # accounts.google.com:sub
        #auth_jwt = request.headers.get( 'X-Goog-IAP-JWT-Assertion' )           # jwt token

        # IAP tokens on S2S will have the SA data - using the params then
        email = request.form.get( "email" )
        sub = request.form.get( "sub" )

        # get user picture (other data on Google Profile are private and cannot be retrieved)
        credentials, _ = auth_data( "https://www.googleapis.com/auth/userinfo.profile" )
        people_api = build( 'people', 'v1', credentials = credentials )

        result = people_api.people().get(
            resourceName = "people/" + sub,
            personFields='names,photos'
        ).execute()

        resp = f"email={email}"

        if "photos" in result:
            url = result[ 'photos' ][ 0 ][ "url" ]
            url = url.replace( "=", ".." )
            resp += f'&photo={url}'

        if "names" in result:
            resp += f'&profile_name={result[ 'names' ][ 0 ][ "displayName" ]}'

        return ( resp, 200 )


    # encrypted calls
    task_dec = decrypt_aes( task, triangle )

    url = "null"
    if host == "cli":
        url = "https://cliente.fablefacet.com"
    if host == "ff":
        url = "https://fablefacet.com"
    response_headers[ "Access-Control-Allow-Origin" ] = url
    #response_headers[ "Access-Control-Allow-Credentials" ] = 'true'


    if task_dec == "texts_index_first_page":
        if bq is None:
            bq = bigquery.Client( project = project_id )

        # this query is optimized, but since texts_index will likely contain only thousands of
        # records at most, it will probably hit the BQ's 10MB minimum anyway. (also the table texts is
        # not clustered using the 'created' column)
        query = """
            WITH daily_counts AS 
            (   SELECT  UNIX_SECONDS( TIMESTAMP_TRUNC( created, DAY )) AS tstamp,
                        COUNT( 1 ) AS total_texts,
                        SUM( COUNT( 1 )) OVER ( ORDER BY 1 DESC ) AS cumulative_texts
                  FROM
                        `fablefacet_data.texts_index`
                 GROUP  BY 
                        tstamp
                 ORDER  BY
                        tstamp DESC -- recent texts first
            ),
            cutoff_timestamp AS 
            (   SELECT
                        MIN( tstamp ) AS min_tstamp
                  FROM
                        (   SELECT  tstamp, cumulative_texts,
                                    LAG( cumulative_texts, 1, 0 ) OVER ( ORDER BY tstamp DESC )
                                        AS prev_cumulative
                              FROM
                                    daily_counts
                        )
                 WHERE
                        prev_cumulative < 100 -- timestamp cutoff for the 100 most recent texts
            )
            SELECT  t.text_id,
                    UNIX_SECONDS( t.created ) AS created,
                    t.author,   t.title,    t.synopsis,
                    t.url,      t.image,    t.tags,
                    ARRAY_AGG
                    (   IF( s.text_id IS NOT NULL,
                            STRUCT
                            (   UNIX_SECONDS( s.created ) AS created,
                                s.version,
                                s.snippet AS reminder
                            ),
                            NULL
                        )
                        IGNORE NULLS
                        ORDER BY s.version ASC
                    )
                        AS versions
              FROM
                    `fablefacet_data.texts_index` t
              LEFT  JOIN
                    `fablefacet_data.texts` s
                ON
                    t.text_id = s.text_id
               AND  s.seq = '0'
             WHERE
                    t.created >= TIMESTAMP_SECONDS( COALESCE(( SELECT min_tstamp FROM cutoff_timestamp ), 0 ))
             GROUP  BY
                    t.text_id, t.created, t.author, t.title, t.synopsis, t.url, t.image, t.tags
             ORDER  BY 
                    t.created DESC
        """

        query_job = bq.query( query )
        rows = query_job.result()

        result = '<data inert="" style="display: none" id="fablefacet_index">'

        for row in rows:
            versions = row[ "versions" ]
            has_saves = len( versions ) > 0
        
            versions_s = "" if not has_saves else (
                f"<data>{''.join([(
                    f'<section data-created="{ v[ "created" ]}" '
                        f'data-version="{ v[ "version" ]}" '
                        f'data-reminder="{ v[ "reminder" ]}"></section>\n'
                )   for v in versions ])}</data>\n" )

            article_s = (
                f'<article id="{row[ "text_id" ]}" '
                f'data-url="{row[ "url" ]}" '
                f'data-image="{row[ "image" ]}" '
                f'data-code="{row[ "text_id" ]}" '
                f'data-created="{row[ "created" ]}" '
                f'data-author="{row[ "author" ]}">\n'
                    f'<details class="synopsis"><summary>{row[ "synopsis" ]}</summary></details>\n'
                    f'<span class="tags">{row[ "tags" ]}</span>\n'
                    '<span class="author"></span>\n'
                    f'{versions_s}'
                f'{row[ 'title' ]}</article>\n' )

            if len( result ) > 100 and ( len( result ) + len( article_s )) > 100000:
                break
            else:
                result += article_s

        result += '</data>'
        enc_res = encrypt_aes( result, triangle )

        return ( enc_res, 200, response_headers )


    # add a reminder to a savepoint (a small note to identify the savept)
    if "reminder::" in task_dec:
        parts = task_dec.split( "::" )

        text_id  = parts[ 1 ]
        version_s = parts[ 3 ]
        reminder = decrypt_aes( request.form.get( 'reminder' ), triangle ).strip()
        if len( reminder ) > 300:
            reminder = reminder[ :300 ]

        if bq is None:
            bq = bigquery.Client( project = project_id )
        query = f"""
            UPDATE  `fablefacet_data.texts`
               SET
                    snippet = '{reminder}'
             WHERE
                    text_id = {text_id}
               AND  version = {version_s}
               AND  seq = '0'
        """

        query_job = bq.query( query )
        query_job.result()

        result = f"<output>reminded affected {query_job.num_dml_affected_rows} row(s)</output>"
        enc_res = encrypt_aes( result, triangle )

        return ( enc_res, 200, response_headers )


    # search for versions of a text - to create the savepoints list
        # if query returns nothing (record doesn't exist), a dummy record is returned,
    # otherwise the client would have to store state to avoid looping
    if "text_load_meta::" in task_dec:
        parts = task_dec.split( "::" )

        text_id  = parts[ 1 ]

        if bq is None:
            bq = bigquery.Client( project = project_id )

        query = f"""
            SELECT  t.text_id,
                    UNIX_SECONDS( t.created ) AS created,
                    t.author,   t.title,    t.synopsis,
                    t.url,      t.image,    t.tags,
                    ARRAY_AGG
                    (   IF( s.text_id IS NOT NULL,
                            STRUCT
                            (   UNIX_SECONDS( s.created ) AS created,
                                s.version,
                                s.snippet AS reminder
                            ),
                            NULL
                        )
                        IGNORE NULLS
                        ORDER BY s.version ASC
                    )
                        AS versions
              FROM
                    `fablefacet_data.texts_index` t
              LEFT  JOIN
                    `fablefacet_data.texts` s
                ON
                    t.text_id = s.text_id
               AND  s.seq = '0'
             WHERE
                    t.text_id = {text_id}
             GROUP  BY
                    t.text_id, t.created, t.author, t.title, t.synopsis, t.url, t.image, t.tags
             ORDER  BY 
                    t.created DESC
        """

        query_job = bq.query( query )
        rows = query_job.result()

        result = '<output>text not found for this user</output>'

        for row in rows:
            versions = row[ "versions" ]
            has_saves = len( versions ) > 0

            versions_s = "" if not has_saves else (
                f"<data>{''.join([(
                    f'<section data-created="{ v[ "created" ]}" '
                        f'data-version="{ v[ "version" ]}" '
                        f'data-reminder="{ v[ "reminder" ]}"></section>\n'
                )   for v in versions ])}</data>\n" )

            article_s = (
                f'<article id="{row[ "text_id" ]}" '
                f'data-url="{row[ "url" ]}" '
                f'data-image="{row[ "image" ]}" '
                f'data-code="{row[ "text_id" ]}" '
                f'data-created="{row[ "created" ]}" '
                f'data-author="{row[ "author" ]}">\n'
                    f'<details class="synopsis"><summary>{row[ "synopsis" ]}</summary></details>\n'
                    f'<span class="tags">{row[ "tags" ]}</span>\n'
                    '<span class="author"></span>\n'
                    f'{versions_s}'
                f'{row[ 'title' ]}</article>\n' )

            result = article_s
            break

        enc_res = encrypt_aes( result, triangle )

        return ( enc_res, 200, response_headers )

    # TODO: REFACT: obsoleta?
    if "snippet_add_verbatim::" in task_dec:
        parts = task_dec.split( "::" )

        # search BigQuery for the main record (ref to codex text)
        # (but it must exists here)
        if bq is None:
            bq = bigquery.Client(project = project_id )

        text_id = parts[ 1 ]
        version = parts[ 2 ]
        snippet = request.form.get( 'snippet' )
        # decrypt the text
        snippet = decrypt_aes( snippet, triangle ).strip()

        # snippet must have data-from
        from_ = snippet[ snippet.find( 'data-from="' ) + 11 : ]
        from_ = snippet[ : snippet.find( '"' )]

        # snippet must have data-device
        device = snippet[ snippet.find( 'data-device="' ) + 13 : ]
        device = snippet[ : snippet.find( '"' )]

        result = add_text( text_id, version, snippet, device, from_ )

        result = "<output>" + result + "</output>"

        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    if "text_del_version::" in task_dec:
        parts = task_dec.split( "::" )

        # search BigQuery for the main record (ref to codex text)
        if bq is None:
            bq = bigquery.Client(project = project_id )

        # parts[ 1 ] = repo url (in the form texts_shard[n]@main_[author-ID]_[text-ID])
        # parts[ 2 ] = text id
        # parts[ 3 ] = version to delete
        text_url = parts[ 1 ]
        text_id = text_url[ text_url.find( "@" ) : ]    # ...main_author-num_text_id
        text_id = text_id[ text_id.find( "_" ) + 1 : ]    # ...author_num/text_id/...
        author = text_id[ : text_id.find( "_" )]
        text_id = parts[ 2 ]
        version = int( parts[ 3 ])

        # check if the version exists
        query = f"""
            SELECT  ARRAY_AGG( DISTINCT version ) as versions
            FROM
                    `fablefacet_data.texts`
            WHERE
                    text_id = {text_id}
        """

        query_job = bq.query( query )
        versions = query_job.result()
        versions = next( iter( versions ), None )

        if versions and versions[ "versions" ] is not None:
            versions = versions[ "versions" ]
        else:
            versions = []

        if version not in versions:
            result = '<output>error: version not found</output>'
        else:
            # DELETE the version
            query = f"""
                DELETE  FROM
                        `fablefacet_data.texts`
                 WHERE
                        text_id = {text_id}
                   AND  version = {version}
            """

            query_job = bq.query( query )
            query_job.result()

            result = f"<output>delete affected {query_job.num_dml_affected_rows} row(s)"

            # if there is no remaining versions, delete the text index record
            if len( versions ) == 1:
                query = f"""
                    DELETE  FROM
                            `fablefacet_data.texts_index`
                    WHERE
                            text_id = {text_id}
                """

                query_job = bq.query( query )
                query_job.result()

                result += " | codex removed - no versions remain"

            result += "</output>"

        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    # TODO: precisamos de um text_load_version para ler uma versao salva no passado?
    if "text_create_version::" in task_dec:
        parts = task_dec.split( "::" )

        # parts[ 1 ] = repo url (in the form texts_shard[n]@main_[author-ID]_[text-ID])
        # parts[ 2 ] = device id
        text_url = parts[ 1 ]
        text_id = text_url[ text_url.find( "@" ) : ]    # ...main_author-num_text_id
        text_id = text_id[ text_id.find( "_" ) + 1 : ]    # ...author_num/text_id/...
        author = text_id[ : text_id.find( "_" )]
        text_id = text_id[ text_id.find( "_" ) + 1 : ]    # ...text_id

        device = parts[ 2 ]

        # request start.md from the repo
        text_url = "https://cdn.jsdelivr.net/gh/fable-facet/" + text_url.replace( "_", "/" )
        text_url = text_url.replace( "texts/shard", "texts_shard" )

        response = requests.get( text_url + "/content/start.md" )

        # search BigQuery for the main record (ref to codex text)
        if bq is None:
            bq = bigquery.Client( project = project_id )

        # start.md should never be missing in a text published in fable facet
        start_md = ""
        if response.status_code == 200:
            start_md = response.text
        else:
            start_md  = "# No start.md page for this text.\n"
            start_md += "You may delete this text and try again if that was just\n"
            start_md += "an internet error. The repo for the text is: "
            start_md += text_url.replace( "https://cdn.jsdelivr.net/gh/", "https://github.com/" ).replace( "@", "/" )
            start_md += ").\n If the error persist, please contact the Author."

        query = f"""
            WITH current_text AS 
            (   SELECT  MAX( version) AS max_version
                  FROM  `fablefacet_data.texts`
                 WHERE  text_id = {text_id}
            ),
            current_index AS 
            (   SELECT  EXISTS
                        ( SELECT  1
                            FROM  `fablefacet_data.texts_index` 
                           WHERE  text_id = {text_id}
                        ) AS exists_flag
            )
            SELECT  COALESCE( ct.max_version, 0 ) AS last_version,
                    ci.exists_flag AS index_exists
              FROM  current_text ct
             CROSS  JOIN 
                    current_index ci
        """
        query_job = bq.query( query )
        last_version = query_job.result()

        version = 1
        index_exists = False
        if last_version.total_rows >= 0:
            for row in last_version:
                version = row[ "last_version" ] + 1
                index_exists = row[ "index_exists" ]
                break

        insert_errors = ""

        # if this is the 1st version, create the main index record too
        if version == 1 and not index_exists:
            # index.js should never be missing in a text published in fable facet
            response = requests.get( text_url + "/index.js" )
            repo_index = None

            if response.status_code == 200:
                repo_index = json.loads( response.text )
            else:
                start_md += "\n\n# No index.js in the repo of the text.\n"
                start_md += "You may delete this text and try again if that was just\n"
                start_md += "an internet error. The repo for the text is: "
                start_md += text_url.replace( "https://cdn.jsdelivr.net/gh/", "https://github.com/" ).replace( "@", "/" )
                start_md += ").\n If the error persist, please contact the Author."

            # cover image must be in index.js
            image = ""
            if repo_index:
                image = [( item[ "path" ], item[ "path" ][ item[ "path" ].rfind( "." ) + 1 : ].strip()) for item in repo_index ]
                image = [ img for img in image if ( "|" + img[ 1 ] + "|" ) in "|jpg|JPG|JPEG|JPG|png|PNG|" ]

                if len( image ) > 0:
                    image = image[ 0 ][ 0 ]
                else:
                    image = ""

            # synopsis is in manifest.mesis (it also must exists in a text published in fable facet repo)
            manifest = ""
            response = requests.get( text_url + "/manifest.mesis" )
            if response.status_code == 200:
                manifest = response.text

            synopsis = ""
            def get_mesis_field( src, field ):
                res = src[ src.find( field ) + len( field ) : ]
                res = res[ res.find( ':' ) + 1 : ]
                res = res.strip()[ 1: ] # first delimiter
                res = res[ : min([ res.find( d ) for d in [ "'", '"', "`" ] if res.find( d ) > -1 ])].strip() # last delimiter

                return res

            if '`summary`' in manifest:
                synopsis = get_mesis_field( manifest, '`summary`' )

            tags = ""
            if '.tags`' in manifest:
                tags = get_mesis_field( manifest, '.tags`' )

            title = get_mesis_field( manifest, 'textContent' )

            # use BQ Storage API to insert
            rows_to_insert = [{ "row_id": str( uuid.uuid4()),
                "text_id": int( text_id ), "created": int( datetime.now( timezone.utc ).timestamp() * 1_000_000),
                "author": int( author ), "title": title, "synopsis": synopsis,
                "url": text_url, "image": image, "tags": tags }]

            response = stream_json_data( project_id, "fablefacet_data", "texts_index", rows_to_insert )

            if response.row_errors:
                err_msgs = [ f"Linha {err.index}: {err.message}" for err in response.row_errors ]
                insert_errors = " | ".join( err_msgs )

            if len( insert_errors ) > 0:
                result = f'<output>error: {insert_errors}</output>'
                enc_res = encrypt_aes( result, triangle )
                return ( enc_res, 200, response_headers )

        # insert the new text version
        rows_to_insert = [{ "row_id": str( uuid.uuid4()),
            "text_id": int( text_id ), "created": int( datetime.now( timezone.utc ).timestamp() * 1_000_000),
            "version": version, "device": device, 
            "from_": "user",    # snippet with sequence num 0 contains the remainder, so it is from the user
            "snippet": "",      # reminder not set at version creation
            "seq": "0", "ref_version": 0, "ref_seq": "0", "ref_seq_end": "0" }]

        response = stream_json_data( project_id, "fablefacet_data", "texts", rows_to_insert )

        result = ""
        if response.row_errors:
            err_msgs = [ f"Linha {err.index}: {err.message}" for err in response.row_errors ]
            insert_errors += " | ".join( err_msgs )
            result = f'<output>error: {insert_errors}</output>'
        else:
            # TODO: REFACT: remover, nao sei pq coloquei aqui, inseria em duplicidade
            # result = add_text( text_id, version, start_md, device, "author" )
            result = f'<output>version created: {version}</output>'

        ipsis_litteris = False
        if( start_md.find( '"ipsis' ) > 0 
                and ( start_md.find( 'litteris"' ) > 0 or start_md.find( 'literis"' ) > 0 )):
            ipsis_litteris = True

        # TODO: remover, o gender_neutral foi removido - mantendo aqui por conta das 24hs do jsdelivr
        if( start_md.find( '"gender' ) > 0 and start_md.find( 'neutral"' ) > 0 ):
            ipsis_litteris = True

        # if start.md has a form, it is immediately sent (the user has to agree with suggestions or change the data)
        form_ = ""
        if start_md.find( "---\n" ):
            form_ = start_md[ start_md.find( "---\n" ) : start_md.rfind( "---\n" )]

        if start_md.find( "---\n" ) > -1:
            result += "<data>" + form_ + "</data>"

        if ipsis_litteris or form_ == "":
            md_contents = start_md
            if md_contents.find( "---\n" ) > 0:
                md_contents = md_contents[ md_contents.rfind( "---\n" ) + 4 : ]

            # start.md do not get a data-subtext attribute. It is part of the codex, but it is meant for the
            # reader / co-author to read it. Notes that are meant to be in the codex but that should not be
            # directly showed to the user must have a data-subtext attr.

            # start.md is part of the codex, but it is treated as a generated or inputed text - the first snippet
            # add to BQ
            rows_to_insert = [{ "row_id": str( uuid.uuid4()),
                "text_id": int( text_id ), "created": int( datetime.now( timezone.utc ).timestamp() * 1_000_000),
                "version": version, "device": device, 
                "from_": "author",    # start.md is from the text main author
                "snippet": start_md,    # stored with the data - data have to be updated later
                "seq": "1", "ref_version": 0, "ref_seq": "0", "ref_seq_end": "0" }]

            response = stream_json_data( project_id, "fablefacet_data", "texts", rows_to_insert )

            if len( form_ ) > 0:
                start_md = start_md[ start_md.rfind( "---\n" ) + 4 : ].strip()

            result += '<data data-snippet="1" data-from="author">' + start_md + "</data>"


        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    # TODO: REFACT: tvz obsoleta, era chamada pela roundtrip, mas esta fn (no wasm principal) foi inativada com o
    # desenvolvim/o do hub - pode tvz ser chamada pelo editor para saber o ultimo numero de sequencia?
    if "text_edit_point::" in task_dec:
        parts = task_dec.split( "::" )

        # search BigQuery for the main record (text codex)
        if bq is None:
            bq = bigquery.Client( project = project_id )

        text_id = parts[ 1 ]
        version = parts[ 2 ]

        query = f"""
            SELECT  COALESCE( MAX( SAFE_CAST( seq as INT64 )), -1 ) as last_seq
            FROM
                    `fablefacet_data.texts`
            WHERE
                    text_id = {text_id}
              AND   version = {version}
              AND   seq NOT LIKE '%::%'
        """

        query_job = bq.query( query )
        last_seq = query_job.result()

        edit_point = -1
        if last_seq.total_rows >= 0:
            for row in last_seq:
                edit_point = row[ "last_seq" ]
                break

        result = f"<output>edit_point__{edit_point}</output>"

        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    if "text_send_data::" in task_dec:
        import xml.etree.ElementTree as ET

        parts = task_dec.split( "::" )
        text_id = parts[ 1 ]
        version = parts[ 2 ]
        device =  parts[ 3 ]

        fields_ = decrypt_aes( request.form.get( 'props' ), triangle ).strip()
        fields_ = fields_.replace( "><", "/><" ).strip()
        fields_ = "<root>" + fields_[ :-1 ] + "/></root>"
        root = ET.fromstring( fields_ )

        # convert data to JSON
        text_replace_data = {}

        for input_tag in root.findall( 'input' ):
            input_id = input_tag.attrib.get( 'id', '' )
            # naming convention: id="role_attr", for instance 'protagonist_name'
            if '_' not in input_id:
                role, attr = input_id, ""
            else:
                role, attr = input_id.split( '_', 1 )

            val = input_tag.attrib.get( 'value' )
            if not val:
                val = input_tag.attrib.get( 'placeholder', '' )

            if val:
                if role not in text_replace_data:
                    if attr != "":
                        text_replace_data[ role ] = {}
                        text_replace_data[ role ][ attr ] = val
                    else:
                        text_replace_data[ role ] = val
                else:
                    if 'dict' not in str( type( text_replace_data[ role ])):
                        text_replace_data[ role ] = { '_default': text_replace_data[ role ]}
                    if attr != "":
                        text_replace_data[ role ][ attr ] = val

        # update data placeholders in BQ
        if bq is None:
            bq = bigquery.Client( project = project_id )

        front_matter = r'\n---'

        newline = r'\n'
        query = f"""
            UPDATE  `fablefacet_data.texts`
               SET  snippet = CONCAT
                    (  '''{json.dumps( text_replace_data )}''',
                       '{newline}',
                       SUBSTR
                       (  snippet, 
                          STRPOS( snippet, '---' ) + 4
                           + STRPOS
                             (  SUBSTR
                                (   snippet, 
                                    STRPOS( snippet, '---' ) + 4 
                                ),
                                '{front_matter}' 
                             ) + 4
                       )
                    ),
                    device = '{device}'
             WHERE  text_id = {text_id}
               AND  version = {version}
               AND  seq = '1'
        """
        query_job = bq.query( query )
        _ = query_job.result()

        # TODO: se start.md NAO tem ipsis litteris, e TEM um form, a IA deve fazer as substituicoes aqui e enviar
        # TODO: REFACT: nao existe mais arquivo na file api, tem q modificar pra usar o BQ
        result = '<output style="display: none">data received</output>'

        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    if "text_user_input::" in task_dec:
        parts = task_dec.split( "::" )
        text_id = parts[ 1 ]
        version = parts[ 2 ]
        device =  parts[ 3 ]

        user_input = decrypt_aes( request.form.get( 'convey' ), triangle ).strip()
        repo_url = decrypt_aes( request.form.get( 'fixed' ), triangle ).strip()
        summary_ = request.form.get( 'sofar', '' )
        if len( summary_ ) > 0:
            summary_ = decrypt_aes( summary_, triangle ).strip()

        result = ""

        # TODO: REFACT: file API abandonada
        # nos user inputs o TODO: sistema de calculo de arquivos relevantes na file API vai enviar
        # a lista como um parametro
        references = decrypt_aes( request.form.get( 'relevant' ), triangle ).strip()
        if len( references ) > 0:
            references = references.split( "||-||" )
        else:
            references = []

        ai_sys = ""
        urls = [ "https://fablefacet.com/ai_sys_proc.md", repo_url + "/description.md", 
            repo_url + "/description-short.md", "https://fablefacet.com/ai_prompt.md",
            repo_url + "/content/blueprint.md" ]

        responses = asyncio.run( parallel_requests( urls ))
        responses = { item[ "url" ].replace( "https://fablefacet.com/", "" ).replace( repo_url + "/", "" ):
                                            item[ "text" ]
                                        for item in responses if item[ "error" ] is None }

        ai_sys = responses[ "ai_sys_proc.md" ]
        ai_prompt = responses[ "ai_prompt.md" ]

        # insert the text blueprint if it exists in the system instructions
            # TODO: enviar opcionalmente do cliente wasm, pra evitar o request
        bluept_start = ai_sys.find( "<blueprint>" ) + 11
        bluept_end = ai_sys.find( "</blueprint>" )

        no_bluept = "content/blueprint.md" not in responses
        if not no_bluept or responses[ "content/blueprint.md" ][ :13 ] == "Couldn't find":
            no_bluept = True

        if not no_bluept:
            bluept = responses[ "content/blueprint.md" ]
        else:
            bluept = "**Main Author did NOT included a blueprint**: this is a free text. Bellow the text description:\n"
            # usa description.md ou description-short, preferencia para description
            if "description.md" in responses:
                bluept = responses[ "description.md" ]
            else:
                bluept = responses[ "description-short.md" ]

        bluept_lines = bluept.split( "\n" )
        bluept_lines = [ line for line in bluept_lines if ":memo:" not in line ]
        bluept = "\n".join( bluept_lines )

        ai_sys = ai_sys[ : bluept_start ] + bluept + ai_sys[ bluept_end : ]

        # insert relevant notes
        notes_start = ai_sys.find( "<codex>" ) + 7
        notes_end = ai_sys.find( "</codex>" )

        ai_sys = ai_sys[ : notes_start ] + "\n".join( references ) + ai_sys[ notes_end : ]

        # insert full summary
        sum_start = ai_sys.find( "<summary>" ) + 9
        sum_end = ai_sys.find( "</summary>" )
        ai_sys = ai_sys[ : sum_start ] + summary_ + ai_sys[ sum_end : ]

        # insert last text window
        window_start = ai_prompt.find( "<recent_history>" ) + 16
        window_end = ai_prompt.find( "</recent_history>" )
        ai_prompt = ai_prompt[ : window_start ] + summary_ + "\n" + user_input + ai_prompt[ window_end : ]

        # compose the summaryzation command
            # TODO: por enquanto so remove os comandos de sumarizacao. Criar sistema de sumario.
        sum_start = ai_prompt.find( "<extra>" )
        sum_end = ai_prompt.find( "</extra>" ) + 8
        ai_prompt = ai_prompt[ : sum_start ] + ai_prompt[ sum_end : ]

        if ai_client is None:
            aistudio_key = get_aistudio_key()
            ai_client = genai.Client( api_key = aistudio_key, http_options = ai_types.HttpOptions( api_version = 'v1alpha' ))

        # TODO: salvar no BQ, obter o num do snippet, esta seq = 2 hardcoded aqui
        result += asyncio.run( gemini_rt( ai_sys, ai_prompt, 2.5, 2 ))

        enc_res = encrypt_aes( result, triangle )
        return ( enc_res, 200, response_headers )


    if "ff_stats::" in task_dec:
        # query para verificar se passamos do 1TB no BQ
        query = """SELECT
          SUM(total_bytes_billed) AS total_bytes_cobrados,
          ROUND(SUM(total_bytes_billed) / POW(1024, 3), 2) AS total_gb,
          ROUND(SUM(total_bytes_billed) / POW(1024, 4), 4) AS total_tb
        FROM
          `region-us`.INFORMATION_SCHEMA.JOBS
        WHERE
          job_type = 'QUERY'
          AND statement_type != 'SCRIPT'
          AND creation_time >= TIMESTAMP(DATE_TRUNC(CURRENT_DATE(), MONTH));"""


    if "debug::" in task_dec:
        aistudio_key = get_aistudio_key()
        enc_res = encrypt_aes( "<output>" + str( aistudio_key ) + "</output>", triangle )
        return ( enc_res, 200, response_headers )


    return ( f'<output>Invalid call - {tstamp}</output>', 200, response_headers )


async def gemini_rt( ai_sys, ai_prompt, ai_model, seq ):
    MODEL_ID = "gemini-2.5-flash-native-audio-latest" #""
    if ai_model == 3:
        MODEL_ID = "gemini-3.1-flash-live-preview"
    if ai_model == 3.8:
        MODEL_ID = "gemini-3.8-live"

    config = ai_types.LiveConnectConfig(
        response_modalities = [ ai_types.Modality.AUDIO ],
        output_audio_transcription = ai_types.AudioTranscriptionConfig(),
        system_instruction = ai_types.Content(
            parts = [ ai_types.Part.from_text( text =ai_sys )]
        ),
    )

    transc_chunks = []
    text_parts = []

    async with ai_client.aio.live.connect( model = MODEL_ID, config = config ) as session:
        await session.send( input = ai_prompt, end_of_turn = True )

        async for response in session.receive():
            server_content = response.server_content

            if server_content is not None:
                model_turn = server_content.model_turn
                transcription = server_content.output_transcription
                if model_turn is not None:
                    for part in model_turn.parts:
                        if part.text:
                            text_parts.append( part.text )
                if transcription and transcription.text:
                        transc_chunks.append( transcription.text )

                if server_content.turn_complete:
                    break

    result = '<output data-model="' + str( ai_model ) + '"></output>'
    result += f'<data data-snippet="{seq}" data-from="ai">'
    if len( transc_chunks ) > 0:
        result += "".join( transc_chunks )
    else:
        result += "".join( text_parts )

    return result + "</data>"


async def parallel_requests( urls ):
    async with httpx.AsyncClient() as client:
        tasks = [ fetch_async( client, url ) for url in urls ]
        responses = await asyncio.gather( *tasks )

    return responses


async def fetch_async( client, url ):
    try:
        response = await client.get( url )
        response.raise_for_status() 
        return { "url": url, "text": response.text, "error": None }

    except Exception as e:
        return { "url": url, "text": None, "error": e }


def stream_json_data( project_id, dataset_id, table_id, json_data ):
    global bq_writer

    if bq_writer is None:
        bq_writer = bigquery_storage_v1.BigQueryWriteClient()

    message_cls = TABLE_MAP.get( table_id )

    parent = f"projects/{project_id}/datasets/{dataset_id}/tables/{table_id}"
    write_stream_path = f"{parent}/streams/_default"

    proto_schema = bq_types.ProtoSchema()
    protobuf_descriptor = descriptor_pb2.DescriptorProto()
    message_cls.DESCRIPTOR.CopyToProto( protobuf_descriptor )
    proto_schema.proto_descriptor = protobuf_descriptor

    proto_rows = bq_types.ProtoRows()

    for row in json_data:
        if "from" in row and "from_" not in row:
            row[ "from_" ] = row.pop( "from" )

        record = message_cls( **row )
        proto_rows.serialized_rows.append( record.SerializeToString())

    request = bq_types.AppendRowsRequest(
        write_stream = write_stream_path,
        proto_rows = bq_types.AppendRowsRequest.ProtoData(
            writer_schema = proto_schema,
            rows = proto_rows
        )
    )

    responses = bq_writer.append_rows( iter([ request ]))

    for response in responses:
        return response


def base64url_encode( data ):
    data_bytes = json.dumps( data ).encode( 'utf-8' )
    return base64.urlsafe_b64encode( data_bytes ).rstrip( b'=' ).decode( 'utf-8' )


def auth_data( scopes = "https://www.googleapis.com/auth/cloud-platform" ):
    if isinstance( scopes, str ):
        scopes = [ scopes ]

    credentials, project_id = google.auth.default(
        scopes= scopes
    )
    credentials.refresh( GoogleRequestTransport())

    return credentials, project_id


def add_text( text_id, version, snippet, device, from_ ):
    global bq

    _, project_id = auth_data()

    # get sequence number (all records have one and it is not automatic because
    # it may not be monotonic)
    query = f"""
        SELECT  COALESCE( MAX( SAFE_CAST( seq as INT64 )), -1 ) as last_seq
          FROM
                `fablefacet_data.texts`
         WHERE
                text_id = {text_id}
           AND  version = {version}
           AND  seq NOT LIKE '%::%'
    """

    if bq is None:
        bq = bigquery.Client( project = project_id )

    query_job = bq.query( query )
    last_seq = query_job.result()

    edit_point = 0
    if last_seq.total_rows >= 0:
        for row in last_seq:
            edit_point = row[ "last_seq" ] + 1
            break

    result = "Error: version not found"
    if edit_point > 0:
        rows_to_insert = [{ "row_id": str( uuid.uuid4()),
            "text_id": int( text_id ), "created": int( datetime.now( timezone.utc ).timestamp() * 1_000_000),
            "version": version, "device": device, 
            "from_": from_,
            "snippet": snippet,
            "seq": str( edit_point ), "ref_version": 0, "ref_seq": "0", "ref_seq_end": "0" }]

        response = stream_json_data( project_id, "fablefacet_data", "texts", rows_to_insert )

        insert_errors = ""
        if response.row_errors:
            err_msgs = [ f"Linha {err.index}: {err.message}" for err in response.row_errors ]
            insert_errors = " | ".join( err_msgs )

        if len( insert_errors ) == 0:
            result = f'snippet added: {text_id}::{version}::{edit_point}'
        else:
            result = f'Error: {insert_errors}'

    return result


def decrypt_aes( encrypted, key_ ):
    #p rint( "key" )
    #p rint( key_ )

    #p rint( "encrypted" )
    #p rint( encrypted )
    to_dec = encrypted.replace( ".", "=" )

    #p rint( "to_dec" )
    #p rint( to_dec )

    iv_b64 = to_dec[ 0:16 ]
    #p rint( "iv b64" )
    #p rint( iv_b64 )
    iv = base64.urlsafe_b64decode( iv_b64.encode( 'utf-8' ))
    #p rint( "iv" )
    #p rint( iv )

    to_dec = to_dec[ 16: ]
    #p rint( "to_dec 2" )
    #p rint( to_dec )
    to_dec = base64.urlsafe_b64decode( to_dec )
    #p rint( "to_dec bytes" )
    #p rint( to_dec )

    #p rint( "key" )
    #p rint( key_ )

    aesgcm = AESGCM( base64.urlsafe_b64decode( key_ ))
    decrypted = aesgcm.decrypt( iv, to_dec, None )

    return decrypted.decode( 'utf-8' )


def encrypt_aes( plain, key_ ):
    enc_data = plain.encode( "utf-8" )
    aesgcm = AESGCM( base64.urlsafe_b64decode( key_ ))

    iv = os.urandom( 12 )
    enc_data = aesgcm.encrypt( iv, enc_data, None ) # ciphertext_with_tag, None = non encrypted data
    enc_data = iv + enc_data
    enc_data = base64.urlsafe_b64encode( enc_data ).decode( "utf-8" )
    enc_data = enc_data.replace( "=", "." )

    return enc_data


def get_triangle():
    credentials, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = build('apikeys', 'v2', credentials=credentials)
    parent = f"projects/{project_id}/locations/global"
    request = service.projects().locations().keys().list(parent=parent)

    try:
        keys_ = request.execute()
        #p rint( keys_ )

    except googleapiclient.errors.HttpError as err:
        print( err.content.decode('utf-8') )
        print( "cannot retrieve API key, YFC can't run" )
        return None, ( "error=no_apis", 200 ), ""

    metakey = None
    uri = ""
    for key_ in keys_[ "keys" ]:
        restr = key_.get( "restrictions", {})
        if "browserKeyRestrictions" in restr and "allowedReferrers" in restr[ "browserKeyRestrictions" ]:
            restr_uris = restr[ "browserKeyRestrictions" ][ "allowedReferrers" ]
            if len( restr_uris ) == 0: 
                continue
            if "https://fablefacet.com" in restr_uris[ 0 ]:
                uri = restr_uris[ 0 ]
                metakey = key_
                break

    if metakey is None:
        print( "cannot retrieve FF metakey, YFC can't run" )
        return None, ( "error=no_metakey", 200 ), ""

    return metakey, None, uri


# TODO: erro no caller (retornar http 500) se a funcao retornar None
def get_aistudio_key():
    # the API key for AIStudio is in another project, because this one needs a billing account
    # (even to stay inside the free tier) but the AIStudio will only operate fully inside the
    # free tier if it is in a project with no billing account
    client = ProjectsClient()

    no_project = True
    api_client = api_keys_v2.ApiKeysClient()
    TGT_SERVICE = "generativelanguage.googleapis.com"
    parent = ""

    no_project = True

    for project in client.search_projects():

        managed_by = project.labels.get( "managed-by", "" )
        proj_role = project.labels.get( "role", "" )
        if managed_by != "fable_facet" or proj_role != "genai-free-tier":
            continue

        # we can find the project but the API Key is not there
        no_project = False

        parent = f"projects/{project.project_id}/locations/global"

        list_request = api_keys_v2.ListKeysRequest( parent = parent )
        for apikey in api_client.list_keys( request = list_request ):
            targets = apikey.restrictions.api_targets if apikey.restrictions else []

            has_llm_target = any( target.service == TGT_SERVICE for target in targets )
            has_metadata = ( apikey.annotations.get( "managed-by" ) == "fable_facet" )

            if has_llm_target and has_metadata:
                key_string_req = api_keys_v2.GetKeyStringRequest( name = apikey.name )
                return api_client.get_key_string( request = key_string_req ).key_string
        break

    project_found = False if no_project else True

    if project_found:
        # the project is there, but API Key is not
        new_key = API_Key()
        new_key.display_name = "ffacet-ai NEVER ADD BILLING"
        new_key.annotations[ "managed-by" ] = "fable_facet"

        api_target = api_keys_v2.ApiTarget()
        api_target.service = TGT_SERVICE
        new_key.restrictions.api_targets = [ api_target ]

        create_req = api_keys_v2.CreateKeyRequest( parent = parent, key = new_key )
        operation = api_client.create_key( request = create_req )
        created_key = operation.result()

        key_string_req = api_keys_v2.GetKeyStringRequest( name = created_key.name )
        api_key_s = api_client.get_key_string( request = key_string_req ).key_string
        return api_key_s

    if no_project:
        return None
