#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93813);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/31 15:42:59 $");

  script_cve_id("CVE-2016-4694", "CVE-2016-4754");
  script_bugtraq_id(93060, 93061);
  script_osvdb_id(136129, 144588);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-09-20-4");

  script_name(english:"macOS : macOS Server < 5.2 Multiple Vulnerabilities (httpoxy)");
  script_summary(english:"Checks the macOS Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for macOS Server.");
  script_set_attribute(attribute:"description", value:
"The version of macOS Server (formerly known as Mac OS X Server)
installed on the remote host is prior to 5.2. It is, therefore,
affected by the following vulnerabilities :

  - The Apache HTTP Server is affected by a
    man-in-the-middle vulnerability known as 'httpoxy' due
    to a failure to properly resolve namespace conflicts in
    accordance with RFC 3875 section 4.1.18. The HTTP_PROXY
    environment variable is set based on untrusted user data
    in the 'Proxy' header of HTTP requests. The HTTP_PROXY
    environment variable is used by some web client
    libraries to specify a remote proxy server. An
    unauthenticated, remote attacker can exploit this, via a
    crafted 'Proxy' header in an HTTP request, to redirect
    an application's internal HTTP traffic to an arbitrary
    proxy server where it may be observed or manipulated.
    (CVE-2016-4694)

  - Multiple unspecified flaws exist that are related to
    the RC4 algorithm that allow an unauthenticated, remote
    attacker to defeat cryptographic protection mechanisms.
    (CVE-2016-4754)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207171");
  # https://lists.apple.com/archives/security-announce/2016/Sep/msg00009.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9b0d4cb");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Server version 5.2 or later. Note that macOS Server
version 5.2 is available only for macOS 10.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:os_x_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "5.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS Server", version);
