#TRUSTED 517ae4f1c364581fcf37d24fe641748eeed4113383c92bbaf81bd541c8a3ab082a8f776150905d5872275c2b290faf2035dc1c829d502fcf940339f21afa1f9748c845abdaff9eb4f70053d7f0c0c0db6a4e38ae9daead9eb125587d21274eabf96e7c1c6ff0c9227a082611fc6b7735e863cec9d2c076bec43e3bc2f969f2bdf9a865e41dd472b102b738ddd25e5b77d4235d953bda594db815b6e9de4d9ca3e43da729a7af4bc047a7788c59c44607e01323f2003155759fa59365fd627c6309e755c56d83720db14142a26495bcffb7dac943f7adad60f8a5ce7a6d3fafc0ce2c6f94411716323bd68d79b27f9b6af681fd27d4923e626140a88878d2b357e3b57ee3b17668e2b2f74528cb8c8c986b61fa10661f3c78a1d8e805891329904f328ecc670896bc6c80638832e8898f8ba9648c5860e1f1ab868a09e21e7a23709f35849e88156f73a44fe2590b5968c2e6c85144a9c00e7bdd4553036f22f352bfefbe880b5c185db53e047d72d20e4e33f2a3e73d3a88595c48e099d5e6ce7a7f1de7a907f10b2ab643d0048266fc4addbd02cd86564e6c290c4a3802a9207dcf84a3458e1df45adf1bef78267f7b5ec56503efd20789dd2e70bc509a4bba376a5c04734fe9573a7599c44b7188a0bc9cbc321526eacd0c998a90395f1d168d2af24017ecf3c35c91d2415fe7eead258ff7d2a88b9df8ff6cd6edecab9d20
#
# @PREFERENCES@
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
# Changes by Tenable :
# - Updated to use compat.inc, made report severity consistent (11/23/09)
# - Added CVSS score, KBs. (11/23/09)
# - Signed. (10/18/2013)
# - Made expiration warning period user-configurable. (05/12/15)
# - Added rsync. (2016/01/07)

if ( ! defined_func("localtime") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(15901);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/01/08");

  script_name(english:"SSL Certificate Expiry");
  script_summary(english:"Checks the SSL certificate expiry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server's SSL certificate has already expired.");
  script_set_attribute(attribute:"description", value:
"This plugin checks expiry dates of certificates associated with SSL-
enabled services on the target and reports whether any have already
expired.");
  script_set_attribute(attribute:"solution", value:
"Purchase or generate a new SSL certificate to replace the existing
one.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2004-2016 George A. Theall");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  script_add_preference(name:"Identify certificates that expire within x days", type:"entry", value:"60");

  exit(0);
}

include("acap_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");
include("x509_func.inc");
include("audit.inc");
include("rsync.inc");

# How far (in days) to warn of certificate expiry.
# Default to 60, and allow the user to customize as long as a non-null, non-zero int is provided
lookahead = 60;
pref = script_get_preference("Identify certificates that expire within x days");
if (pref =~ "^\d+$")
{
  pref = int(pref);
  if (pref > 0)
    lookahead = pref;
}

set_kb_item(name:'SSL/settings/future_warning_days', value:lookahead);

# This function converts a date expressed as:
#   Year(4)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var gtime, i, mm, mon, mons, parts, year;
  mons = "JanFebMarAprMayJunJulAugSepOctNovDec";

  if (x509time && x509time =~ "^[0-9]{14}Z?$") {
    parts[0] = substr(x509time, 0, 3);
    for (i=1; i<= 6; ++i) {
      parts[i] = substr(x509time, 2+i*2, 2+i*2+1);
    }

    year = int(parts[0]);

    mm = int(parts[1]);
    if (mm >= 1 && mm <= 12) {
      --mm;
      mon = substr(mons, mm*3, mm*3+2);
    }
    else {
      mon = "unk";
    }
    parts[2] = ereg_replace(string:parts[2], pattern:"^0", replace:" ");

    gtime = string(
      mon, " ",
      parts[2], " ",
      parts[3], ":", parts[4], ":", parts[5], " ",
      year, " GMT"
    );
  }
  return gtime;
}

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# Open socket, sending StartTLS commands if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "Failed to connect to port " + port + ".");

# Retrieve the certificate the server is using for this port.
cert = get_server_cert(socket:soc, port:port, encoding:"der");
if (isnull(cert))
  exit(1, "Failed to read server cert from port " + port + ".");

# nb: maybe someday I'll actually *parse* ASN.1.
v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
if (v >= 0) {
  v += 4;
  valid_start = substr(cert, v, v+11);
  v += 15;
  valid_end = substr(cert, v, v+11);

  if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
    # nb: YY >= 50 => YYYY = 19YY per RFC 3280 (4.1.2.5.1)
    if (int(substr(valid_start, 0, 1)) >= 50) valid_start = "19" + valid_start;
    else valid_start = "20" + valid_start;

    if (int(substr(valid_end, 0, 1)) >= 50) valid_end = "19" + valid_end;
    else valid_end = "20" + valid_end;

    # Get dates, expressed in UTC, for checking certs.
    # - right now.
    tm = localtime(unixtime(), utc:TRUE);
    now = string(tm["year"]);
    foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
      if (tm[field] < 10) now += "0";
      now += tm[field];
    }
    # - 'lookahead' days in the future.
    tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
    future = string(tm["year"]);
    foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
      if (tm[field] < 10) future += "0";
      future += tm[field];
    }
    debug_print("now:    ", now, ".");
    debug_print("future: ", future, ".");

    valid_start_alt = x509time_to_gtime(x509time:valid_start);
    valid_end_alt = x509time_to_gtime(x509time:valid_end);
    debug_print("valid not before: ", valid_start_alt, " (", valid_start, "Z).");
    debug_print("valid not after:  ", valid_end_alt,   " (", valid_end, "Z).");

    debug_print("The SSL certificate on port ", port, " is valid between ", valid_start_alt, " and ", valid_end_alt, ".", level:1);

    # Extract the issuer / subject.
    cert2 = parse_der_cert(cert:cert);
    if (isnull(cert2))
      exit(1, "Failed to parse the SSL certificate associated with the service on port " + port + ".");

    tbs = cert2["tbsCertificate"];
    issuer_seq = tbs["issuer"];
    subject_seq = tbs["subject"];

    issuer = '';
    foreach seq (issuer_seq)
    {
      o = oid_name[seq[0]];
      if (isnull(o)) continue;

      attr = "";
      if (o == "Common Name") attr = "CN";
      else if (o == "Surname") attr = "SN";
      else if (o == "Country") attr = "C";
      else if (o == "Locality") attr = "L";
      else if (o == "State/Province") attr = "ST";
      else if (o == "Street") attr = "street";
      else if (o == "Organization") attr = "O";
      else if (o == "Organization Unit") attr = "OU";
      else if (o == "Email Address") attr = "emailAddress";

      if (attr) issuer += ', ' + attr + '=' + seq[1];
    }
    if (issuer) issuer = substr(issuer, 2);
    else issuer = 'n/a';

    subject = '';
    foreach seq (subject_seq)
    {
      o = oid_name[seq[0]];
      if (isnull(o)) continue;

      attr = "";
      if (o == "Common Name") attr = "CN";
      else if (o == "Surname") attr = "SN";
      else if (o == "Country") attr = "C";
      else if (o == "Locality") attr = "L";
      else if (o == "State/Province") attr = "ST";
      else if (o == "Street") attr = "street";
      else if (o == "Organization") attr = "O";
      else if (o == "Organization Unit") attr = "OU";
      else if (o == "Email Address") attr = "emailAddress";

      if (attr) subject += ', ' + attr + '=' + seq[1];
    }
    if (subject) subject = substr(subject, 2);
    else subject = 'n/a';

    if (valid_start > now)
    {
      set_kb_item(name:'Transport/SSL/'+port+'/future_validity_date', value:valid_start_alt);
      set_kb_item(name:'Transport/SSL/'+port+'/issuer', value:issuer);
      set_kb_item(name:'Transport/SSL/'+port+'/subject', value:subject);
      set_kb_item(name:'Transport/SSL/'+port+'/valid_end_alt', value:valid_end_alt);
    }

    else if (valid_end < now)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' + 'The SSL certificate has already expired :' +
          '\n' +
          '\n  Subject          : ' + subject +
          '\n  Issuer           : ' + issuer +
          '\n  Not valid before : ' + valid_start_alt +
          '\n  Not valid after  : ' + valid_end_alt + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      set_kb_item(name:'Transport/SSL/'+port+'/expired_cert', value:TRUE);
    }
    else if (valid_end < future)
    {
      set_kb_item(name:'Transport/SSL/'+port+'/days_to_expire', value:lookahead);
      set_kb_item(name:'Transport/SSL/'+port+'/future_expiry_date', value:valid_end_alt);
      set_kb_item(name:'Transport/SSL/'+port+'/issuer', value:issuer);
      set_kb_item(name:'Transport/SSL/'+port+'/subject', value:subject);
      set_kb_item(name:'Transport/SSL/'+port+'/valid_start_alt', value:valid_start_alt);
    }
  }
}
