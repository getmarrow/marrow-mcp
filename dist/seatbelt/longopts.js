"use strict";
// Fixed lists of the long options that the seatbelt parsers understand, in full spelling (patch round 3).
//
// Why: GNU tools (and git, curl and wget) accept a long option shortened to any unique prefix, so a parser that
// only knows the full spelling can misread what a command writes: `cp --target=<dir> src` writes into <dir>,
// `git reset --har` resets the working tree, `git grep --open-f=<cmd>` runs <cmd>. The parsers therefore never
// read a long option by prefix. Each parser has a list below; a long option counts as one of them only on an exact
// match (with `=value` only where the option takes one). Any other long option (shortened, unknown, ambiguous)
// makes that parser give its strictest answer: a writer treats every operand as a destination, a reader is not a
// reader (the operand rule applies), a git read-only or index-only check says "not read-only", and an option that
// would loosen an answer never counts unless it is spelled exactly.
//
// The lists were generated once from the tools' own --help output on a GNU/Linux machine (GNU coreutils 9.4,
// tar 1.35, sed 4.9, grep 3.11, diffutils, curl 8.5, wget 1.21, rsync 3.2.7, jq, ripgrep 15, git 2.43), then
// reviewed by hand: an option that writes or runs something is not on a reader's list (less --log-file,
// rg --pre, bat --pager, yq --inplace, file --compile, prettier --write). Nothing is read from the machine at
// run time. Options a list does not hold stay strict, which only matters when a command also names a protected
// path.
Object.defineProperty(exports, "__esModule", { value: true });
exports.FIND_LONG = exports.GIT_RESTORE_LONG = exports.GIT_RM_LONG = exports.GIT_RESET_LONG = exports.GIT_GLOBAL_LONG = exports.GIT_READ_LONG = exports.DOAS_LONG = exports.SUDO_LONG = exports.ENV_LONG = exports.ZIP_LONG = exports.PRETTIER_LONG = exports.TREE_LONG = exports.RG_LONG = exports.MORE_LONG = exports.LESS_LONG = exports.BAT_LONG = exports.YQ_LONG = exports.JQ_LONG = exports.CHECKSUM_LONG = exports.GREP_LONG = exports.FILE_LONG = exports.CMP_LONG = exports.DIFF_LONG = exports.DU_LONG = exports.LS_LONG = exports.STAT_LONG = exports.WC_LONG = exports.TAIL_LONG = exports.HEAD_LONG = exports.CAT_LONG = exports.SCP_LONG = exports.RSYNC_LONG = exports.WGET_LONG = exports.CURL_LONG = exports.SED_LONG = exports.TAR_LONG = exports.INSTALL_LONG = exports.LN_LONG = exports.MV_LONG = exports.CP_LONG = exports.NO_LONG = void 0;
exports.longList = longList;
exports.unknownLongAll = unknownLongAll;
exports.unknownLong = unknownLong;
exports.takesNextWord = takesNextWord;
exports.longValue = longValue;
/**
 * Builds a list from text. Tokens are separated by spaces: `name` (no value), `name=` (a value), `name[=]` (an
 * optional value), `name~` (any form). A leading `[no-]` adds the `no-name` form (no value).
 */
function longList(text) {
    const map = new Map();
    for (const raw of text.split(/\s+/)) {
        if (raw === '')
            continue;
        let token = raw;
        const negated = token.startsWith('[no-]');
        if (negated)
            token = token.slice(5);
        let mode = 'n';
        if (token.endsWith('[=]')) {
            mode = 'o';
            token = token.slice(0, -3);
        }
        else if (token.endsWith('=')) {
            mode = 'v';
            token = token.slice(0, -1);
        }
        else if (token.endsWith('~')) {
            mode = 'a';
            token = token.slice(0, -1);
        }
        map.set(token, mode);
        if (negated)
            map.set(`no-${token}`, 'n');
    }
    return map;
}
/**
 * The indexes of the long options in `words` that are not on `list` (exact name; `=value` only where the option
 * takes one); empty when every long option is on it. A bare `--` ends the options when `honourEnd` is set. A value
 * word that belongs to a listed option (`--name value`) is skipped. `dashes` is 2 for `--name`; find writes its
 * options as `-name` (1), where `=` is never part of an option. A word with no readable text is not a long option here
 * (each parser already treats it on its own).
 */
function unknownLongAll(words, list, dashes = 2, honourEnd = true) {
    const lead = '-'.repeat(dashes);
    const found = [];
    for (let i = 0; i < words.length; i += 1) {
        const t = words[i].text;
        if (t === null)
            continue;
        if (honourEnd && t === '--')
            break;
        if (!t.startsWith(lead) || t.length <= dashes)
            continue;
        const eq = dashes === 2 ? t.indexOf('=') : -1;
        const name = eq === -1 ? t.slice(dashes) : t.slice(dashes, eq);
        const mode = list.get(name);
        if (mode === undefined || (eq !== -1 && mode === 'n')) {
            found.push(i);
            continue;
        }
        if (eq === -1 && mode === 'v')
            i += 1;
    }
    return found;
}
/** The index of the first long option that is not on `list` (see unknownLongAll), or -1. */
function unknownLong(words, list, dashes = 2, honourEnd = true) {
    const found = unknownLongAll(words, list, dashes, honourEnd);
    return found.length === 0 ? -1 : found[0];
}
/** True for a word that is exactly `--name` of a listed option that takes its value as the next word. */
function takesNextWord(text, list) {
    return text.startsWith('--') && !text.includes('=') && list.get(text.slice(2)) === 'v';
}
/** The text after `=` of a `--name=value` word, or null when there is none. */
function longValue(text) {
    const eq = text.indexOf('=');
    return text.startsWith('--') && eq !== -1 ? text.slice(eq + 1) : null;
}
exports.NO_LONG = longList('');
exports.CP_LONG = longList('archive attributes-only backup[=] context[=] copy-contents debug dereference force help interactive link ' +
    'no-clobber no-dereference no-preserve= no-target-directory one-file-system parents preserve[=] recursive ' +
    'reflink[=] remove-destination sparse= strip-trailing-slashes suffix= symbolic-link target-directory= ' +
    'update[=] verbose version');
exports.MV_LONG = longList('backup[=] context debug force help interactive no-clobber no-copy no-target-directory strip-trailing-slashes ' +
    'suffix= target-directory= update[=] verbose version');
exports.LN_LONG = longList('backup[=] directory force help interactive logical no-dereference no-target-directory physical relative ' +
    'suffix= symbolic target-directory= verbose version');
exports.INSTALL_LONG = longList('backup[=] compare context[=] debug directory group= help mode= no-target-directory owner= preserve-context ' +
    'preserve-timestamps strip strip-program= suffix= target-directory= verbose version');
exports.TAR_LONG = longList('absolute-names acls add-file= after-date= anchored append atime-preserve[=] auto-compress backup[=] ' +
    'block-number blocking-factor= bzip2 catenate check-device check-links checkpoint[=] checkpoint-action= ' +
    'clamp-mtime compare compress concatenate confirmation create delay-directory-restore delete dereference diff ' +
    'directory= exclude= exclude-backups exclude-caches exclude-caches-all exclude-caches-under exclude-from= ' +
    'exclude-ignore= exclude-ignore-recursive= exclude-tag= exclude-tag-all= exclude-tag-under= exclude-vcs ' +
    'exclude-vcs-ignores extract file= files-from= force-local format= full-time get group= group-map= gunzip ' +
    'gzip hard-dereference help hole-detection= ignore-case ignore-command-error ignore-failed-read ignore-zeros ' +
    'incremental index-file= info-script= interactive keep-directory-symlink keep-newer-files keep-old-files ' +
    'label= level= list listed-incremental= lzip lzma lzop mode= mtime= multi-volume new-volume-script= newer= ' +
    'newer-mtime= no-acls no-anchored no-auto-compress no-check-device no-delay-directory-restore no-ignore-case ' +
    'no-ignore-command-error no-null no-overwrite-dir no-quote-chars= no-recursion no-same-owner ' +
    'no-same-permissions no-seek no-selinux no-unquote no-verbatim-files-from no-wildcards ' +
    'no-wildcards-match-slash no-xattrs null numeric-owner occurrence[=] old-archive one-file-system ' +
    'one-top-level[=] overwrite overwrite-dir owner= owner-map= pax-option= portability posix preserve-order ' +
    'preserve-permissions quote-chars= quoting-style= read-full-records record-size= recursion recursive-unlink ' +
    'remove-files restrict rmt-command= rsh-command= same-order same-owner same-permissions seek selinux ' +
    'show-defaults show-omitted-dirs show-snapshot-field-ranges show-stored-names show-transformed-names ' +
    'skip-old-files sort= sparse sparse-version= starting-file= strip-components= suffix= tape-length= test-label ' +
    'to-command= to-stdout totals[=] touch transform= uncompress ungzip unlink-first unquote update usage ' +
    'use-compress-program= utc verbatim-files-from verbose verify version volno-file= warning= wildcards ' +
    'wildcards-match-slash xattrs xattrs-exclude= xattrs-include= xform= xz zstd');
exports.SED_LONG = longList('debug expression= file= follow-symlinks help in-place[=] line-length= null-data posix quiet regexp-extended ' +
    'sandbox separate silent unbuffered version');
exports.CURL_LONG = longList('abstract-unix-socket~ alt-svc~ anyauth~ append~ aws-sigv4~ basic~ ca-native~ cacert~ capath~ cert~ ' +
    'cert-status~ cert-type~ ciphers~ compressed~ compressed-ssh~ config~ connect-timeout~ connect-to~ ' +
    'continue-at~ cookie~ cookie-jar~ create-dirs~ create-file-mode~ crlf~ crlfile~ curves~ data~ data-ascii~ ' +
    'data-binary~ data-raw~ data-urlencode~ delegation~ digest~ disable~ disable-eprt~ disable-epsv~ ' +
    'disallow-username-in-url~ dns-interface~ dns-ipv4-addr~ dns-ipv6-addr~ dns-servers~ doh-cert-status~ ' +
    'doh-insecure~ doh-url~ dump-header~ egd-file~ engine~ etag-compare~ etag-save~ expect100-timeout~ fail~ ' +
    'fail-early~ fail-with-body~ false-start~ form~ form-escape~ form-string~ ftp-account~ ' +
    'ftp-alternative-to-user~ ftp-create-dirs~ ftp-method~ ftp-pasv~ ftp-port~ ftp-pret~ ftp-skip-pasv-ip~ ' +
    'ftp-ssl-ccc~ ftp-ssl-ccc-mode~ ftp-ssl-control~ get~ globoff~ happy-eyeballs-timeout-ms~ haproxy-clientip~ ' +
    'haproxy-protocol~ head~ header~ help~ hostpubmd5~ hostpubsha256~ hsts~ http0.9~ http1.0~ http1.1~ http2~ ' +
    'http2-prior-knowledge~ http3~ http3-only~ ignore-content-length~ include~ insecure~ interface~ ipfs-gateway~ ' +
    'ipv4~ ipv6~ json~ junk-session-cookies~ keepalive-time~ key~ key-type~ krb~ libcurl~ limit-rate~ list-only~ ' +
    'local-port~ location~ location-trusted~ login-options~ mail-auth~ mail-from~ mail-rcpt~ ' +
    'mail-rcpt-allowfails~ manual~ max-filesize~ max-redirs~ max-time~ metalink~ negotiate~ netrc~ netrc-file~ ' +
    'netrc-optional~ next~ no-alpn~ no-buffer~ no-clobber~ no-keepalive~ no-npn~ no-progress-meter~ no-sessionid~ ' +
    'noproxy~ ntlm~ ntlm-wb~ oauth2-bearer~ output~ output-dir~ parallel~ parallel-immediate~ parallel-max~ pass~ ' +
    'path-as-is~ pinnedpubkey~ post301~ post302~ post303~ preproxy~ progress-bar~ proto~ proto-default~ ' +
    'proto-redir~ proxy~ proxy-anyauth~ proxy-basic~ proxy-ca-native~ proxy-cacert~ proxy-capath~ proxy-cert~ ' +
    'proxy-cert-type~ proxy-ciphers~ proxy-crlfile~ proxy-digest~ proxy-header~ proxy-http2~ proxy-insecure~ ' +
    'proxy-key~ proxy-key-type~ proxy-negotiate~ proxy-ntlm~ proxy-pass~ proxy-pinnedpubkey~ proxy-service-name~ ' +
    'proxy-ssl-allow-beast~ proxy-ssl-auto-client-cert~ proxy-tls13-ciphers~ proxy-tlsauthtype~ ' +
    'proxy-tlspassword~ proxy-tlsuser~ proxy-tlsv1~ proxy-user~ proxy1.0~ proxytunnel~ pubkey~ quote~ ' +
    'random-file~ range~ rate~ raw~ referer~ remote-header-name~ remote-name~ remote-name-all~ remote-time~ ' +
    'remove-on-error~ request~ request-target~ resolve~ retry~ retry-all-errors~ retry-connrefused~ retry-delay~ ' +
    'retry-max-time~ sasl-authzid~ sasl-ir~ service-name~ show-error~ silent~ socks4~ socks4a~ socks5~ ' +
    'socks5-basic~ socks5-gssapi~ socks5-gssapi-nec~ socks5-gssapi-service~ socks5-hostname~ speed-limit~ ' +
    'speed-time~ ssl~ ssl-allow-beast~ ssl-auto-client-cert~ ssl-no-revoke~ ssl-reqd~ ssl-revoke-best-effort~ ' +
    'sslv2~ sslv3~ stderr~ styled-output~ suppress-connect-headers~ tcp-fastopen~ tcp-nodelay~ telnet-option~ ' +
    'tftp-blksize~ tftp-no-options~ time-cond~ tls-max~ tls13-ciphers~ tlsauthtype~ tlspassword~ tlsuser~ tlsv1~ ' +
    'tlsv1.0~ tlsv1.1~ tlsv1.2~ tlsv1.3~ tr-encoding~ trace~ trace-ascii~ trace-config~ trace-ids~ trace-time~ ' +
    'unix-socket~ upload-file~ url~ url-query~ use-ascii~ user~ user-agent~ variable~ verbose~ version~ ' +
    'write-out~ xattr~');
exports.WGET_LONG = longList('accept~ accept-regex~ adjust-extension~ append-output~ ask-password~ auth-no-challenge~ background~ ' +
    'backup-converted~ backups~ base~ bind-address~ body-data~ body-file~ ca-certificate~ ca-directory~ ' +
    'certificate~ certificate-type~ ciphers~ compression~ config~ connect-timeout~ content-disposition~ ' +
    'content-on-error~ continue~ convert-file-only~ convert-links~ crl-file~ cut-dirs~ debug~ default-page~ ' +
    'delete-after~ directory-prefix~ dns-timeout~ domains~ exclude-directories~ exclude-domains~ execute~ ' +
    'follow-ftp~ follow-tags~ force-directories~ force-html~ ftp-password~ ftp-user~ ftps-clear-data-connection~ ' +
    'ftps-fallback-to-ftp~ ftps-implicit~ ftps-resume-ssl~ header~ help~ hsts-file~ http-password~ http-user~ ' +
    'https-only~ ignore-case~ ignore-length~ ignore-tags~ include-directories~ inet4-only~ inet6-only~ ' +
    'input-file~ keep-session-cookies~ level~ limit-rate~ load-cookies~ local-encoding~ max-redirect~ method~ ' +
    'mirror~ no-cache~ no-check-certificate~ no-clobber~ no-config~ no-cookies~ no-directories~ no-dns-cache~ ' +
    'no-glob~ no-host-directories~ no-hsts~ no-http-keep-alive~ no-if-modified-since~ no-iri~ no-netrc~ ' +
    'no-parent~ no-passive-ftp~ no-proxy~ no-remove-listing~ no-use-server-timestamps~ no-verbose~ ' +
    'no-warc-compression~ no-warc-digests~ no-warc-keep-log~ output-document~ output-file~ page-requisites~ ' +
    'password~ pinnedpubkey~ post-data~ post-file~ prefer-family~ preserve-permissions~ private-key~ ' +
    'private-key-type~ progress~ protocol-directories~ proxy-password~ proxy-user~ quiet~ quota~ random-file~ ' +
    'random-wait~ read-timeout~ recursive~ referer~ regex-type~ reject~ reject-regex~ rejected-log~ relative~ ' +
    'remote-encoding~ report-speed~ restrict-file-names~ retr-symlinks~ retry-connrefused~ retry-on-host-error~ ' +
    'retry-on-http-error~ save-cookies~ save-headers~ secure-protocol~ server-response~ show-progress~ ' +
    'span-hosts~ spider~ start-pos~ strict-comments~ timeout~ timestamping~ tries~ trust-server-names~ unlink~ ' +
    'use-askpass~ user~ user-agent~ verbose~ version~ wait~ waitretry~ warc-cdx~ warc-dedup~ warc-file~ ' +
    'warc-header~ warc-max-size~ warc-tempdir~ xattr~');
exports.RSYNC_LONG = longList('8-bit-output~ acls~ address~ append~ append-verify~ archive~ atimes~ backup~ backup-dir~ block-size~ ' +
    'blocking-io~ bwlimit~ checksum~ checksum-choice~ checksum-seed~ chmod~ chown~ compare-dest~ compress~ ' +
    'compress-choice~ compress-level~ contimeout~ copy-as~ copy-dest~ copy-devices~ copy-dirlinks~ copy-links~ ' +
    'copy-unsafe-links~ crtimes~ cvs-exclude~ debug~ del~ delay-updates~ delete~ delete-after~ delete-before~ ' +
    'delete-delay~ delete-during~ delete-excluded~ delete-missing-args~ devices~ dirs~ dry-run~ early-input~ ' +
    'exclude~ exclude-from~ executability~ existing~ fake-super~ files-from~ filter~ force~ from0~ fsync~ fuzzy~ ' +
    'group~ groupmap~ hard-links~ help~ human-readable~ iconv~ ignore-errors~ ignore-existing~ ' +
    'ignore-missing-args~ ignore-times~ include~ include-from~ info~ inplace~ ipv4~ ipv6~ itemize-changes~ ' +
    'keep-dirlinks~ link-dest~ links~ list-only~ log-file~ log-file-format~ max-alloc~ max-delete~ max-size~ ' +
    'min-size~ mkpath~ modify-window~ munge-links~ no-implied-dirs~ no-motd~ numeric-ids~ old-args~ old-d~ ' +
    'old-dirs~ omit-dir-times~ omit-link-times~ one-file-system~ only-write-batch~ open-noatime~ out-format~ ' +
    'outbuf~ owner~ partial~ partial-dir~ password-file~ perms~ port~ preallocate~ progress~ protocol~ ' +
    'prune-empty-dirs~ quiet~ read-batch~ recursive~ relative~ remote-option~ remove-source-files~ rsh~ ' +
    'rsync-path~ safe-links~ secluded-args~ size-only~ skip-compress~ sockopts~ sparse~ specials~ stats~ stderr~ ' +
    'stop-after~ stop-at~ suffix~ super~ temp-dir~ timeout~ times~ trust-sender~ update~ usermap~ verbose~ ' +
    'version~ whole-file~ write-batch~ write-devices~ xattrs~');
exports.SCP_LONG = longList('');
exports.CAT_LONG = longList('help number number-nonblank show-all show-ends show-nonprinting show-tabs squeeze-blank version');
exports.HEAD_LONG = longList('bytes= help lines= quiet silent verbose version zero-terminated');
exports.TAIL_LONG = longList('bytes= follow[=] help lines= max-unchanged-stats= pid= quiet retry silent sleep-interval= verbose version ' +
    'zero-terminated');
exports.WC_LONG = longList('bytes chars files0-from= help lines max-line-length total= version words');
exports.STAT_LONG = longList('cached= dereference file-system format= help printf= terse version');
exports.LS_LONG = longList('all almost-all author block-size= classify[=] color[=] context dereference dereference-command-line ' +
    'dereference-command-line-symlink-to-dir directory dired escape file-type format= full-time ' +
    'group-directories-first help hide= hide-control-chars human-readable hyperlink[=] ignore= ignore-backups ' +
    'indicator-style= inode kibibytes literal no-group numeric-uid-gid quote-name quoting-style= recursive ' +
    'reverse show-control-chars si size sort= tabsize= time= time-style= version width= zero');
exports.DU_LONG = longList('all apparent-size block-size= bytes count-links dereference dereference-args exclude= exclude-from= ' +
    'files0-from= help human-readable inodes max-depth= no-dereference null one-file-system separate-dirs si ' +
    'summarize threshold= time= time-style= total version');
exports.DIFF_LONG = longList('brief changed-group-format= color[=] context[=] ed exclude= exclude-from= expand-tabs from-file= help ' +
    'horizon-lines= ifdef= ignore-all-space ignore-blank-lines ignore-case ignore-file-name-case ' +
    'ignore-matching-lines= ignore-space-change ignore-tab-expansion ignore-trailing-space initial-tab label= ' +
    'left-column line-format= minimal new-file new-group-format= new-line-format= no-dereference ' +
    'no-ignore-file-name-case normal old-group-format= old-line-format= paginate palette= rcs recursive ' +
    'report-identical-files show-c-function show-function-line= side-by-side speed-large-files starting-file= ' +
    'strip-trailing-cr suppress-blank-empty suppress-common-lines tabsize= text to-file= unchanged-group-format= ' +
    'unchanged-line-format= unidirectional-new-file unified[=] version width=');
exports.CMP_LONG = longList('bytes= help ignore-initial= print-bytes quiet silent verbose version');
exports.FILE_LONG = longList('apple brief checking-printout debug dereference exclude= exclude-quiet= extension files-from= help ' +
    'keep-going list magic-file= mime mime-encoding mime-type no-buffer no-dereference no-pad no-sandbox ' +
    'parameter preserve-date print0 raw separator= special-files uncompress uncompress-noreport version');
exports.GREP_LONG = longList('after-context= basic-regexp before-context= binary binary-files= byte-offset color[=] colour[=] context= ' +
    'count dereference-recursive devices= directories= exclude= exclude-dir= exclude-from= extended-regexp file= ' +
    'files-with-matches files-without-match fixed-strings group-separator= help ignore-case include= initial-tab ' +
    'invert-match label= line-buffered line-number line-regexp max-count= no-filename no-group-separator ' +
    'no-ignore-case no-messages null null-data only-matching perl-regexp quiet recursive regexp= silent text ' +
    'version with-filename word-regexp');
exports.CHECKSUM_LONG = longList('algorithm= base64 binary check debug help ignore-missing length= portable quiet raw status strict tag text ' +
    'untagged version warn zero');
exports.JQ_LONG = longList('arg argjson args ascii-output build-configuration color-output compact-output exit-status from-file help ' +
    'indent join-output jsonargs library-path= monochrome-output null-input raw-input raw-output raw-output0 ' +
    'rawfile seq slurp slurpfile sort-keys stream stream-errors tab unbuffered version');
exports.YQ_LONG = longList('output-format= input-format= indent= prettyPrint colors no-colors unwrapScalar no-doc null-input exit-status ' +
    'verbose version help nul-output yaml-output yaml-roundtrip xml-output toml-output width= compact-output ' +
    'raw-output join-output slurp sort-keys tab arg= argjson= raw-input ascii-output csv-auto-parse ' +
    'tsv-auto-parse csv-separator=');
exports.BAT_LONG = longList('language= style= theme= color= decorations= paging= plain number show-all line-range= highlight-line= tabs= ' +
    'wrap= terminal-width= italic-text= force-colorization file-name= diff diff-context= list-languages ' +
    'list-themes map-syntax= ignored-suffix= nonprintable-notation= unbuffered strip-ansi= squeeze-blank ' +
    'squeeze-limit= binary= no-config no-custom-assets help version');
exports.LESS_LONG = longList('quit-at-eof QUIT-AT-EOF quit-if-one-screen quiet silent QUIET SILENT raw-control-chars RAW-CONTROL-CHARS ' +
    'chop-long-lines line-numbers LINE-NUMBERS ignore-case IGNORE-CASE no-init no-keypad squeeze-blank-lines ' +
    'hilite-search HILITE-SEARCH long-prompt LONG-PROMPT status-column tilde incsearch use-color jump-target= ' +
    'tabs= shift= pattern= prompt= tag= follow-name redraw-on-quit mouse MOUSE wheel-lines= version help');
exports.MORE_LONG = longList('silent logical no-pause print-over clean-print squeeze plain lines= number= help version');
exports.RG_LONG = longList('after-context= auto-hybrid-regex before-context= binary block-buffered byte-offset case-sensitive color= ' +
    'colors= column context= context-separator= count count-matches crlf debug dfa-size-limit= encoding= engine= ' +
    'field-context-separator= field-match-separator= file= files files-with-matches files-without-match ' +
    'fixed-strings follow generate= glob= glob-case-insensitive heading help hidden hyperlink-format= iglob= ' +
    'ignore-case ignore-file= ignore-file-case-insensitive include-zero invert-match json line-buffered ' +
    'line-number line-regexp max-columns= max-columns-preview max-count= max-depth= max-filesize= mmap multiline ' +
    'multiline-dotall no-config no-filename no-ignore no-ignore-dot no-ignore-exclude no-ignore-files ' +
    'no-ignore-global no-ignore-messages no-ignore-parent no-ignore-vcs no-line-number no-messages ' +
    'no-pcre2-unicode no-require-git no-unicode null null-data one-file-system only-matching passthru ' +
    'path-separator= pcre2 pcre2-version pretty quiet regex-size-limit= regexp= replace= search-zip smart-case ' +
    'sort= sort-files sortr= stats stop-on-nonmatch text threads= trace trim type= type-add= type-clear= ' +
    'type-list type-not= unrestricted version vimgrep with-filename word-regexp no-heading no-hidden no-follow ' +
    'no-mmap no-multiline no-stats no-trim no-column no-json no-search-zip no-binary no-crlf no-fixed-strings ' +
    'no-invert-match no-line-buffered no-one-file-system no-sort-files no-text no-block-buffered no-byte-offset ' +
    'no-context-separator no-encoding no-include-zero no-ignore-file-case-insensitive no-glob-case-insensitive ' +
    'no-max-columns-preview no-auto-hybrid-regex no-multiline-dotall no-pcre2 messages unicode ignore-vcs ' +
    'ignore-dot ignore-exclude ignore-files ignore-global ignore-messages ignore-parent require-git pcre2-unicode ' +
    'print0 maxdepth ignore passthrough');
exports.TREE_LONG = longList('help version inodes device noreport nolinks dirsfirst filesfirst charset= filelimit= timefmt= sort= fromfile ' +
    'fromtabfile info gitignore gitfile= ignore-case matchdirs metafirst prune du si hintro= houtro= opt-toggle');
exports.PRETTIER_LONG = longList('check list-different help version ignore-unknown no-color color no-editorconfig no-config ' +
    'no-error-on-unmatched-pattern ignore-path= log-level= stdin-filepath= parser= print-width= tab-width= ' +
    'use-tabs no-use-tabs semi no-semi single-quote no-single-quote jsx-single-quote no-jsx-single-quote ' +
    'quote-props= trailing-comma= bracket-spacing no-bracket-spacing bracket-same-line no-bracket-same-line ' +
    'arrow-parens= prose-wrap= html-whitespace-sensitivity= vue-indent-script-and-style ' +
    'no-vue-indent-script-and-style end-of-line= embedded-language-formatting= single-attribute-per-line ' +
    'no-single-attribute-per-line insert-pragma require-pragma range-start= range-end= cache no-cache ' +
    'cache-strategy= with-node-modules experimental-ternaries object-wrap= experimental-operator-position=');
exports.ZIP_LONG = longList('recurse-paths quiet verbose junk-paths no-dir-entries symlinks exclude= include= freshen update grow ' +
    'filesync display-counts display-dots output-file= temp-path= help version');
// The wrappers that can change the working folder of the command they run (patch round 4). Full spellings from each
// tool's own documentation: GNU env 9.4 (`env --help`), sudo 1.9 (`sudo --help` and the manual), OpenBSD doas (it has
// no long option at all). A long option that is not on a list could be a chdir option (GNU tools read a unique
// prefix, `env --chd=DIR`), so the working folder is unknown then.
exports.ENV_LONG = longList('ignore-environment null unset= chdir= split-string= block-signal[=] default-signal[=] ignore-signal[=] list-signal-handling debug help version');
exports.SUDO_LONG = longList('askpass bell preserve-env[=] set-home remove-timestamp no-update preserve-groups stdin version background edit help login reset-timestamp ' +
    'list non-interactive shell validate close-from= chdir= chroot= command-timeout= other-user= group= host= prompt= role= type= user=');
exports.DOAS_LONG = longList('');
exports.GIT_READ_LONG = longList('abbrev~ abbrev-commit~ abbrev-ref~ absolute-git-dir~ after~ after-context~ ahead-behind~ aliases~ all~ ' +
    'all-match~ allow-unknown-type~ alternate-refs~ always~ amend~ ancestry-path~ anchored~ and~ annotate-stdin~ ' +
    'author~ author-date-order~ base~ basic-regexp~ batch~ batch-all-objects~ batch-check~ batch-command~ before~ ' +
    'before-context~ binary~ bisect~ bisect-all~ bisect-vars~ boundary~ branch~ branches~ break~ break-rewrites~ ' +
    'broken~ buffer~ cached~ candidates~ cc~ check~ cherry~ cherry-mark~ cherry-pick~ children~ chmod~ cleanup~ ' +
    'clear-decorations~ color~ color-by-age~ color-lines~ color-moved~ color-moved-ws~ color-words~ column~ ' +
    'combined~ combined-all-paths~ commit-header~ committer~ compact-summary~ config~ contains~ contents~ ' +
    'context~ count~ cumulative~ date~ date-order~ dd~ debug~ decorate~ decorate-refs~ decorate-refs-exclude~ ' +
    'deduplicate~ default~ default-prefix~ deleted~ dense~ developer-interfaces~ diff-algorithm~ diff-filter~ ' +
    'diff-merges~ directory~ dirstat~ dirstat-by-file~ dirty~ disk-usage~ do-walk~ dry-run~ dst-prefix~ edit~ ' +
    'email~ empty-directory~ encoding~ end-of-options~ eol~ error-unmatch~ exact-match~ exclude~ ' +
    'exclude-first-parent-only~ exclude-from~ exclude-hidden~ exclude-per-directory~ exclude-promisor-objects~ ' +
    'exclude-standard~ exit-code~ expand-tabs~ ext-diff~ ext-grep~ extended-regexp~ external-commands~ file~ ' +
    'files-with-matches~ files-without-match~ filter~ filters~ find-copies~ find-copies-harder~ find-object~ ' +
    'find-renames~ first-parent~ fixed-strings~ fixup~ flags~ follow~ follow-symlinks~ force~ format~ full-diff~ ' +
    'full-history~ full-index~ full-name~ full-tree~ function-context~ git-common-dir~ git-dir~ git-path~ glob~ ' +
    'gpg-sign~ graph~ grep~ grep-reflog~ group~ guides~ header~ heading~ help~ help-all~ histogram~ ' +
    'human-readable~ ignore-all-space~ ignore-blank-lines~ ignore-case~ ignore-cr-at-eol~ ignore-errors~ ' +
    'ignore-matching-lines~ ignore-missing~ ignore-removal~ ignore-rev~ ignore-revs-file~ ignore-space-at-eol~ ' +
    'ignore-space-change~ ignore-submodules~ ignored~ in-commit-order~ include~ incremental~ indent-heuristic~ ' +
    'index~ indexed-objects~ info~ intent-to-add~ inter-hunk-context~ interactive~ invert-grep~ invert-match~ ' +
    'irreversible-delete~ is-bare-repository~ is-inside-git-dir~ is-inside-work-tree~ is-shallow-repository~ ' +
    'ita-invisible-in-index~ ita-visible-in-index~ killed~ left-only~ left-right~ line-number~ line-porcelain~ ' +
    'line-prefix~ log-size~ long~ mailmap~ man~ match~ max-age~ max-count~ max-depth~ max-parents~ merge~ ' +
    'merge-base~ merges~ message~ min-age~ min-parents~ minimal~ missing~ modified~ name-only~ name-status~ ' +
    'no-abbrev~ no-abbrev-commit~ no-after-context~ no-ahead-behind~ no-aliases~ no-all~ no-all-match~ ' +
    'no-allow-unknown-type~ no-always~ no-amend~ no-annotate-stdin~ no-author~ no-basic-regexp~ ' +
    'no-before-context~ no-branch~ no-break~ no-broken~ no-buffer~ no-cached~ no-candidates~ no-chmod~ ' +
    'no-cleanup~ no-color~ no-color-by-age~ no-color-lines~ no-color-moved~ no-color-moved-ws~ no-column~ ' +
    'no-commit-header~ no-commit-id~ no-committer~ no-compact-summary~ no-contains~ no-contents~ no-context~ ' +
    'no-count~ no-date~ no-debug~ no-decorate~ no-decorate-refs~ no-decorate-refs-exclude~ no-deduplicate~ ' +
    'no-deleted~ no-diff-merges~ no-directory~ no-dirty~ no-dry-run~ no-edit~ no-email~ no-empty-directory~ ' +
    'no-eol~ no-error-unmatch~ no-exact-match~ no-exclude~ no-exclude-per-directory~ no-exclude-standard~ ' +
    'no-exit-code~ no-ext-diff~ no-ext-grep~ no-extended-regexp~ no-external-commands~ no-file~ ' +
    'no-files-with-matches~ no-files-without-match~ no-find-copies-harder~ no-first-parent~ no-fixed-strings~ ' +
    'no-fixup~ no-flags~ no-follow~ no-follow-symlinks~ no-force~ no-full-index~ no-full-name~ no-full-tree~ ' +
    'no-function-context~ no-gpg-sign~ no-group~ no-heading~ no-human-readable~ no-ignore-case~ no-ignore-errors~ ' +
    'no-ignore-matching-lines~ no-ignore-missing~ no-ignore-removal~ no-ignore-rev~ no-ignore-revs-file~ ' +
    'no-ignore-submodules~ no-ignored~ no-include~ no-incremental~ no-indent-heuristic~ no-index~ no-info~ ' +
    'no-intent-to-add~ no-interactive~ no-invert-match~ no-killed~ no-line-number~ no-line-porcelain~ no-long~ ' +
    'no-mailmap~ no-man~ no-match~ no-max-count~ no-max-parents~ no-merges~ no-message~ no-min-parents~ ' +
    'no-minimal~ no-modified~ no-name-only~ no-non-matching~ no-notes~ no-null~ no-numbered~ no-object-names~ ' +
    'no-only~ no-only-matching~ no-open-files-in-pager~ no-others~ no-patch~ no-path~ no-pathspec-file-nul~ ' +
    'no-pathspec-from-file~ no-perl-regexp~ no-porcelain~ no-post-rewrite~ no-prefix~ no-progress~ no-quiet~ ' +
    'no-recurse-submodules~ no-recursive~ no-reedit-message~ no-refresh~ no-refs~ no-relative~ no-rename-empty~ ' +
    'no-renames~ no-renormalize~ no-reset-author~ no-resolve-undo~ no-reuse-message~ no-revs~ no-root~ ' +
    'no-score-debug~ no-short~ no-show-email~ no-show-function~ no-show-name~ no-show-number~ no-show-stash~ ' +
    'no-show-stats~ no-signoff~ no-source~ no-sparse~ no-squash~ no-stage~ no-status~ no-stdin~ no-summary~ ' +
    'no-tags~ no-template~ no-text~ no-textconv~ no-threads~ no-undefined~ no-unmerged~ no-unordered~ ' +
    'no-untracked~ no-untracked-files~ no-update~ no-use-mailmap~ no-verbose~ no-verify~ no-walk~ no-web~ ' +
    'no-with-tree~ no-word-regexp~ non-matching~ not~ notes~ null~ numbered~ numstat~ object-names~ object-only~ ' +
    'objects~ objects-edge~ objects-edge-aggressive~ oneline~ only~ only-matching~ open-files-in-pager~ or~ ' +
    'orderfile~ others~ ours~ output~ output-indicator-context~ output-indicator-new~ output-indicator-old~ ' +
    'parents~ patch~ patch-with-raw~ patch-with-stat~ path~ pathspec-file-nul~ pathspec-from-file~ patience~ ' +
    'perl-regexp~ pickaxe-all~ pickaxe-regex~ porcelain~ post-rewrite~ prefix~ pretty~ progress~ quiet~ raw~ ' +
    'recurse-submodules~ recursive~ reedit-message~ reflog~ refresh~ refs~ regexp-ignore-case~ relative~ ' +
    'relative-date~ remerge-diff~ remotes~ remove-empty~ rename-empty~ renames~ renormalize~ reset-author~ ' +
    'resolve-git-dir~ resolve-undo~ reuse-message~ reverse~ revs-only~ right-only~ root~ rotate-to~ score-debug~ ' +
    'shared-index-path~ short~ shortstat~ show-cdup~ show-email~ show-function~ show-linear-break~ show-name~ ' +
    'show-notes~ show-notes-by-default~ show-number~ show-object-format~ show-prefix~ show-pulls~ show-signature~ ' +
    'show-stash~ show-stats~ show-superproject-working-tree~ show-toplevel~ signoff~ simplify-by-decoration~ ' +
    'simplify-merges~ since~ since-as-filter~ single-worktree~ skip~ skip-to~ source~ sparse~ sq-quote~ squash~ ' +
    'src-prefix~ stage~ staged~ standard-notes~ stat~ stat-count~ stat-graph-width~ stat-name-width~ stat-width~ ' +
    'status~ stdin~ submodule~ summary~ symbolic~ symbolic-full-name~ tags~ template~ text~ textconv~ theirs~ ' +
    'threads~ timestamp~ topo-order~ trailer~ undefined~ unified~ unmerged~ unordered~ unpacked~ until~ ' +
    'untracked~ untracked-files~ update~ use-bitmap-index~ use-mailmap~ user-interfaces~ verbose~ verify~ ' +
    'walk-reflogs~ web~ with-tree~ word-diff~ word-diff-regex~ word-regexp~ ws-error-highlight~');
exports.GIT_GLOBAL_LONG = longList('git-dir= work-tree= namespace= exec-path[=] super-prefix= config-env= attr-source= list-cmds= no-pager ' +
    'paginate bare no-replace-objects literal-pathspecs glob-pathspecs noglob-pathspecs icase-pathspecs ' +
    'no-optional-locks no-lazy-fetch no-advice html-path man-path info-path version help');
exports.GIT_RESET_LONG = longList('mixed soft quiet no-quiet patch no-patch intent-to-add no-intent-to-add pathspec-from-file= ' +
    'no-pathspec-from-file pathspec-file-nul no-pathspec-file-nul refresh no-refresh');
exports.GIT_RM_LONG = longList('cached no-cached dry-run no-dry-run force no-force ignore-unmatch no-ignore-unmatch quiet no-quiet sparse ' +
    'no-sparse pathspec-from-file= no-pathspec-from-file pathspec-file-nul no-pathspec-file-nul');
exports.GIT_RESTORE_LONG = longList('staged no-staged source= patch no-patch quiet no-quiet progress no-progress pathspec-from-file= ' +
    'no-pathspec-from-file pathspec-file-nul no-pathspec-file-nul ignore-unmerged no-ignore-unmerged');
exports.FIND_LONG = longList('H L P D= O0 O1 O2 O3 - help version daystart depth follow ignore_readdir_race maxdepth= mindepth= mount ' +
    'noignore_readdir_race noleaf regextype= warn nowarn xdev amin= anewer= atime= cmin= cnewer= ctime= empty ' +
    'executable false fstype= gid= group= ilname= iname= inum= ipath= iregex= iwholename= links= lname= mmin= ' +
    'mtime= name= newer= nogroup nouser path= perm= readable regex= samefile= size= true type= uid= used= user= ' +
    'wholename= writable xtype= context= print print0 prune quit ls printf= not and or a o d E s x X f= acl ' +
    'flags= mnewer= sparse neweraa= neweraB= newerac= neweram= newerat= newerBa= newerBB= newerBc= newerBm= ' +
    'newerBt= newerca= newercB= newercc= newercm= newerct= newerma= newermB= newermc= newermm= newermt=');
//# sourceMappingURL=longopts.js.map