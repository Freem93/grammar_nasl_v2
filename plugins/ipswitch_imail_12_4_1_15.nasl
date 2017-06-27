#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76490);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160", "CVE-2014-3878");
  script_bugtraq_id(66363, 66690, 67830);
  script_osvdb_id(104810, 105465, 107700, 107701, 107702);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"EDB-ID", value:"33633");

  script_name(english:"Ipswitch IMail Server 11.x / 12.x < 12.4.1.15 Multiple Vulnerabilities (Heartbleed)");
  script_summary(english:"Checks versions of Ipswitch IMail services");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ipswitch IMail Server 11.x or
12.x older than version 12.4.1.15 and is, therefore, potentially
affected by the following vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material and other protected content.
    (CVE-2014-0160)

  - Multiple input validation errors exist related to the
    'WebClient' component that could allow cross-site
    scripting attacks. (CVE-2014-3878)");
  # http://docs.ipswitch.com/_Messaging/IMailServer/v12.4.1/ReleaseNotes/index.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0313fdff");
  # http://www.imailserver.com/support/patches-upgrades/imail-server-v12-4-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61f33454");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");

  script_set_attribute(attribute:"solution", value:"Upgrade to Ipswitch IMail Server version 12.4.1.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl","imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

ver = NULL;
service = NULL;
source  = NULL;

# - SMTP.
ports = get_kb_list("Services/smtp");
if (isnull(ports)) ports = make_list(25);
foreach port (ports)
{
  if (get_port_state(port) && !get_kb_item('SMTP/'+port+'/broken'))
  {
    banner = get_smtp_banner(port:port);
    # At least keep trying to find a banner
    if (isnull(banner) || strlen(banner) == 0) continue;

    if (" (IMail " >< banner)
    {
      pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "SMTP";
            source  = match;
            break;
          }
        }
      }
      if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail SMTP", port);
    }
    else
      if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail SMTP", port);
  }
}

# - IMAP.
if (isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_imap_banner(port:port);
      # At least keep trying to find a banner
      if (isnull(banner) || strlen(banner) == 0) continue;

      if (" (IMail " >< banner)
      {
        pat = "IMAP4 Server[^(]+\(IMail ([0-9.]+) *([0-9]+-[0-9]+)?\)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              service = "IMAP";
              source = match;
              break;
            }
          }
        }
        if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail IMAP", port);
      }
      else
        if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail IMAP", port);
    }
  }
}

# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_pop3_banner(port:port);
      # At least keep trying to find a banner
      if (isnull(banner) || strlen(banner) == 0) continue;

      if (" (IMail " >< banner)
      {
        pat = "NT-POP3 Server .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              service = "POP3";
              source  = match;
              break;
            }
          }
        }
        if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail POP3", port);
      }
      else
        if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail POP3", port);
    }
  }
}

if (isnull(ver)) audit(AUDIT_SERVICE_VER_FAIL, "Ipswitch IMail Server", port);

# There's a problem if the version is 11.x / 12.x < 12.4.1.15
if (
  ver =~ "^(11|12)\." &&
  ver_compare(ver:ver, fix:'12.4.1.15', strict:FALSE) < 0
)
{
  # To avoid confusion or strange output,
  # XSS flag is being set on port 0; we
  # do not necessarily know which HTTP port
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Service            : ' + service +
      '\n  Version source     : ' + source + 
      '\n  Installed version  : ' + ver +
      '\n  Fixed version      : 12.4.1.15' +
      '\n';
   security_hole(port:port,extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Ipswitch IMail Server", port, ver);
