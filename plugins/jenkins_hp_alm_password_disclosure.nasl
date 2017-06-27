#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73302);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_bugtraq_id(64621);
  script_osvdb_id(101505, 101506);

  script_name(english:"Jenkins HP Application Automation Tools Plugin Password Encryption Security Weakness");
  script_summary(english:"Attempts to enumerate unprotected passwords");

  script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a password disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using the Jenkins HP Application Automation tools
plugin. Nessus was able to remotely access one or more unprotected
file(s) in the Jenkins build system and decrypt the HP Application
Lifecycle Management password. These passwords are currently encrypted
with a known, hard-coded key.");
  script_set_attribute(attribute:"see_also", value:"https://issues.jenkins-ci.org/browse/JENKINS-17515");
  script_set_attribute(attribute:"solution", value:
"The are no known patches for this issue. As a workaround, restrict
access to affected systems.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include("audit.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# handles PKCS #7 padding
# and checks that decrypted data is printable ASCII,
# since that is what we are expecting
function handlePadding(plain_text)
{
  local_var i, pad_bytes, counted_pad_bytes, ret;

  pad_bytes = NULL;
  counted_pad_bytes = 0;

  for (i=0; i<strlen(plain_text); i++)
  {
    if (!isnull(pad_bytes))
    {
      # all pad pytes should be the same value
      # e.g. 0x03 0x03 0x03 (3 byte pad)
      if (ord(plain_text[i]) != pad_bytes)
        return NULL;
      counted_pad_bytes++;
    }
    else
    {
      if (is_ascii_printable(char:plain_text[i]))
        ret += plain_text[i];
      else # not printable, most likely padding
      {
        pad_bytes = ord(plain_text[i]);
        # padding will be 1 to 7 bytes
        if (pad_bytes <= 0 || pad_bytes > 7)
          return NULL;
        counted_pad_bytes++;
      }
    }
  }
  # check number of pad bytes = pad byte value
  if (!isnull(pad_bytes))
    if (pad_bytes != counted_pad_bytes) return NULL;

  return ret;
}

# decrypt HP alm password
function decryptPassword(encoded_encrypted_pass)
{
  local_var encryption_key, ret, res;

  encoded_encrypted_pass = str_replace(find:"\", replace:"", string:encoded_encrypted_pass);

  # the source code has 'EncriptionPass4Java' as the key, but the encryption routine
  # only uses the first 16 bytes for the key (128 bits)
  encryption_key = "EncriptionPass4J";

  res = aes_cbc_decrypt(data:base64_decode(str:encoded_encrypted_pass),
                        key:encryption_key,
                        iv:encryption_key);

  # check that decryption was successful
  if (isnull(res[0]) || res[0] == '' || res[0] % 16 != 0) return NULL;

  ret = handlePadding(plain_text:res[0]);
  return ret;
}

# search buf for pattern and return group matches
function getMatchList(pattern, buf, group, limit)
{
  local_var tmp_list, item, i;

  tmp_list = make_list();

  item = eregmatch(pattern:pattern, string:buf);

  i = 0;
  while(!isnull(item) && !isnull(item[group]))
  {
    i++;
    buf -= item[0]; # we don't want to find the same thing again
    tmp_list = make_list(tmp_list, item[group]);
    item = eregmatch(pattern:pattern, string:buf);
    if (!isnull(limit) && i >= limit) break;
  }

  return list_uniq(tmp_list);
}

port = get_http_port(default:8080);
get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

# find list of Jobs
res = http_send_recv3(item:"/",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

job_list = getMatchList(pattern:'<a class="model-link inside" href="job/([^/]+)/">([^<]+)</a>',
                        buf:res[2], group:1);

if (max_index(job_list) == 0)
  exit(0, "Unable to find any jobs for Jenkins install on port " + port + ".");

targets = make_array();

# Find property files for each job workspace
foreach job (job_list)
{
  res = http_send_recv3(item:"/job/" + job + "/ws/",
                        port:port,
                        method:"GET",
                        exit_on_fail:TRUE);

  # workspaces should be cleared out periodically automatically (usually after a successful build or
  # after 10 runs), but limit number of property files to look at in case we have a very large number
  # of builds
  file_list = getMatchList(pattern:'<a href="(props[0-9]+\\.txt)/\\*view\\*/">view</a>',
                           buf:res[2], group:1, limit:25);

  if (max_index(file_list) != 0)
    targets[job] = file_list;
}

if (max_index(keys(targets)) == 0)
  exit(0, "Unable to find any property files containing password information.");

report = '';

# examine property file, confirm it's for HP ALM plugin, and try to decrypt
# HP ALM Password
foreach job (keys(targets))
{
  foreach file (targets[job])
  {
    project = NULL;
    domain = NULL;
    password = NULL;
    username = NULL;
    server = NULL;

    path = '/job/' + job + '/ws/' + file;
    res = http_send_recv3(item:path,
                          port:port,
                          method:"GET",
                          exit_on_fail:TRUE);

    fields_found = 0;

    foreach line (split(res[2], sep:'\n', keep:FALSE))
    {
      line = chomp(line);

      if (ereg(pattern:"^almDomain=", string:line) ||
         ereg(pattern:"^almRunHost=", string:line) ||
         ereg(pattern:"^almProject=", string:line) ||
         ereg(pattern:"^almServerUrl=", string:line))
        fields_found++;

      item = eregmatch(pattern:"^almUserName=(.+)$", string:line);
      if (!isnull(item) && !isnull(item[1]) && item[1] != '')
        username = item[1];

      item = eregmatch(pattern:"^almPassword=([A-Za-z0-9+/\\=]+)$", string:line);
      if (!isnull(item) && !isnull(item[1]))
        password = decryptPassword(encoded_encrypted_pass:item[1]);

      item = eregmatch(pattern:"^almDomain=(.+)$", string:line);
      if (!isnull(item) && !isnull(item[1]))
        domain = item[1];

      item = eregmatch(pattern:"^almProject=(.+)$", string:line);
      if (!isnull(item) && !isnull(item[1]))
        project = item[1];

      item = eregmatch(pattern:"^almServerUrl=(.+)$", string:line);
      if (!isnull(item) && !isnull(item[1]))
        server = str_replace(find:"\", replace:"", string:item[1]);
    }

    if (fields_found != 4 || isnull(password)) continue;

    password = password[0] + crap(data:'*', length:6) + password[strlen(password)-1];

    report += '\n  Unprotected Property File URL : ' + build_url(qs:path, port:port);

    if (!isnull(username))
      report += '\n  HP ALM Username               : ' + username;
    if (!isnull(domain))
      report += '\n  HP ALM Domain                 : ' + domain;
    if (!isnull(project))
      report += '\n  HP ALM Project                : ' + project;
    if (!isnull(server))
      report += '\n  HP ALM Server                 : ' + server;

    report += '\n  Decrypted Password            : ' + password + ' (sanitized)\n';
    break;

  }
  if (report != '' && !thorough_tests) break;
}

if (report == '')
  audit(AUDIT_LISTEN_NOT_VULN, "Jenkins", port);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
