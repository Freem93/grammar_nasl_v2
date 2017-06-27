#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19592);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2011/11/18 20:42:30 $");

  script_cve_id("CVE-2005-2797", "CVE-2005-2798", "CVE-2006-0393");
  script_bugtraq_id(14727, 14729, 19289);
  script_osvdb_id(19141, 19142, 27745);

  script_name(english:"OpenSSH < 4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for GSSAPI credential disclosure vulnerability in OpenSSH");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host has the following vulnerabilities :

  - X11 forwarding may be enabled unintentionally when
    multiple forwarding requests are made on the same session,
    or when an X11 listener is orphaned after a session goes
    away. (CVE-2005-2797)

  - GSSAPI credentials may be delegated to users who
    log in using something other than GSSAPI authentication
    if 'GSSAPIDelegateCredentials' is enabled. (CVE-2005-2798)

  - Attempting to log in as a nonexistent user causes
    the authentication process to hang, which could
    be exploited to enumerate valid user accounts.
    Only OpenSSH on Mac OS X 10.4.x is affected.
    (CVE-2006-0393)

  - Repeatedly attempting to log in as a nonexistent
    user could result in a denial of service.
    Only OpenSSH on Mac OS X 10.4.x is affected.
    (CVE-2006-0393)");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-4.2");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Aug/msg00000.html");
  script_set_attribute(attribute:"see_also",value:"http://docs.info.apple.com/article.html?artnum=304063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.2 or later.  For OpenSSH on Mac OS X 10.4.x,
apply Mac OS X Security Update 2006-004." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/07");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/01");
  script_set_attribute(attribute:"patch_publication_date", value: "2005/09/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (bp_banner =~ "openssh[-_]([0-3]\.|4\.[01])")
  security_note(port);
