#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25737);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id(
    "CVE-2007-2795", 
    "CVE-2007-3925", 
    "CVE-2007-3926", 
    "CVE-2007-3927"
  );
  script_bugtraq_id(24962);
  script_osvdb_id(36219, 36220, 36221, 36222, 44952, 45818, 45819);

  script_name(english:"Ipswitch IMail Server < 2006.21 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Ipswitch IMail");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch IMail, a commercial messaging and
collaboration suite for Windows. 

According to its banner, the version of Ipswitch IMail installed on
the remote host has several buffer overflows in its IMAP service
component, one of which can be exploited prior to authentication to
execute arbitrary code with SYSTEM privileges. 

In addition, there is also an denial of service issue that can cause
the IM Server to crash without authentication.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?194eb0fd");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/474040/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-042.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-043.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/275");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/277");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/im200621.asp");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch IMail version 2006.21 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ipswitch IMail IMAP SEARCH Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/19");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);
  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

function check(port, proto, ver, banner)
{
  local_var	report;

  if (! ver) return;
  # There's a problem if it's < 9.21 (== 2006.21).
  if (ver =~ "^([0-8]\.|9\.(0[0-9]$|[12]$))")
  {
    if (report_verbosity < 1)
      security_hole(port);
    else
    {
      report = '\n' +
'The installed version is : ' + ver + '\n' +
'The patched version is   : 9.21\n';
      if (report_verbosity > 1)
        report += 'The '+proto+' banner on this port is :\n\n' + banner + '\n';
      security_hole(port:port, extra: report);
    }
# NB: it's possible to customize the banner, but unless thorough checks
#     are enabled, we'll just stop.
    if (! thorough_tests) exit(0);
  }
}


# Do banner checks of various ports.
#
# - SMTP.
pl = get_kb_list("Services/smtp");
if (isnull(pl)) pl = make_list(25);

foreach port (pl)
{
  if (!get_port_state(port)) continue;
  if (get_kb_item('SMTP/'+port+'/broken')) continue;
banner = get_smtp_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  check(port: port, ver: ver, banner: banner, proto: 'SMTP');
}
}

# - POP3.
pl = get_kb_list("Services/pop3");
if (isnull(pl)) pl = make_list(110);
foreach port(pl)
{
  if (!get_port_state(port)) continue;

banner = get_pop3_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "NT-POP3 Server .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  check(port: port, ver: ver, banner: banner, proto: 'POP3');
}
}

# - IMAP.
pl = get_kb_list("Services/imap");
if (isnull(pl)) pl = make_list(143);
foreach port(pl)
{
  if (!get_port_state(port)) continue;

banner = get_imap_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "IMAP4 Server \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  check(port: port, ver: ver, banner: banner, proto: 'IMAP');
}
}
