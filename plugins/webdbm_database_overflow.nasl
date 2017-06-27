#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22309);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-4305");
  script_bugtraq_id(19660);
  script_osvdb_id(28300);

  script_name(english:"SAP DB / MaxDB WebDBM Client Database Name Remote Overflow");
  script_summary(english:"Gets version of Web DBM");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SAP DB or MaxDB, a SAP-certified open-
source database supporting OLTP and OLAP. 

According to its version, the Web DBM component of MaxDB on the remote
host reportedly contains a buffer overflow that can be triggered by an
HTTP request containing a long database name.  An unauthenticated
remote attacker may be able to exploit this flaw to execute arbitrary
code on the affected host subject to the privileges of the 'wahttp'
process. 

Note that on Windows the 'wahttp' process runs with 'SYSTEM'
privileges so a successful attack may result in a complete compromise
of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/content/en/us/enterprise/research/SYMSA-2006-009.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444601/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Web DBM version 7.6.00.31 or later as that is reported to
fix the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MaxDB WebDBM Database Parameter Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/29");
 script_cvs_date("$Date: 2014/05/29 04:24:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 9999);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Exit unless we're being paranoid or the target is running Windows
# to avoid false-positives with, say, the Debian MaxDB package.
os = get_kb_item("Host/OS");
if (report_paranoia < 2 && os && "Windows" >!< os) exit(0);


port = get_http_port(default:9999);

# Make sure the banner indicates it's Web DBM.
banner = get_http_banner(port:port);
if (!banner || "Server: SAP-Internet-SapDb-Server" >!< banner) exit(0);


# Get the version number.
r = http_send_recv3(method:"GET", item:"/webdbm?Page=VERSION", port:port);
if (isnull(r)) exit(0);
res = r[2];

ver = NULL;
build = NULL;
pat = '<td class="(dbmSTbvCellStd|dbmSTbvCellLast|table[0-9]).*>(&nbsp;)*([0-9][
0-9.-]+) *(&nbsp;)*</';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    m = eregmatch(pattern:pat, string:match);
    if (!isnull(m))
    {
      if ("table" >< m[1] && m[3] !~ "^[0-9]{3}-") ver = chomp(m[3]);
      if ("CellStd" >< m[1]) ver = chomp(m[3]);
      if ("CellLast" >< m[1] || ("table" >< m[1] && m[3] =~ "^[0-9]{3}-"))
      {
        build = m[3];
        if (build =~ "^([0-9][0-9][0-9])-.*")
        {
          build = ereg_replace(pattern:"^([0-9][0-9][0-9])-.*", replace:"\1", string:build);
          build = int(build);
        }
      }
    }
  }
}
if (isnull(ver)) exit(0);
if (!isnull(build)) ver += "." + build;


# There's a problem if the version is under 7.6.00.31.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 7 ||
  (
    int(iver[0]) == 7 &&
    (
      int(iver[1]) < 6 ||
      (int(iver[1]) == 6 && int(iver[2]) == 0 && !isnull(iver[3]) && int(iver[3]) < 31)
    )
  )
)
{
  report = string(
    "According to its banner, MaxDB / SAP DB version ", ver, " is installed\n",
    "on the remote host.\n"
  );
  security_hole(port:port, extra: report);
}

