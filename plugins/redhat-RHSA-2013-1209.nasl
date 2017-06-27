#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72238);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id(
    "CVE-2012-3499",
    "CVE-2012-4558",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-1921",
    "CVE-2013-2172",
    "CVE-2013-4112"
  );
  script_bugtraq_id(58165, 59826, 60846, 61129, 61179, 62256);
  script_osvdb_id(90556, 90557, 93366, 94651, 95386, 95498, 96980);
  script_xref(name:"RHSA", value:"2013:1209");

  script_name(english:"JBoss Enterprise Application Platform 6.1.1 Update (RHSA-2013:1209)");
  script_summary(english:"Checks for the install versions of JBoss Enterprise Application Platform");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform installed on the
remote system is affected by the following issues :

  - Flaws in the mod_info, mod_status, mod_imagemap,
    mod_ldap, and mod_proxy_ftp modules can allow an
    attacker to perform cross-site scripting (XSS) attacks.
    (CVE-2012-3499)

  - Flaws in the web interface of the mod_proxy_balancer
    module can allow a remote attacker to perform XSS
    attacks. (CVE-2012-4558)

  - A flaw in mod_rewrite can allow remote attackers to
    execute arbitrary commands via an HTTP request
    containing an escape sequence for a terminal emulator.
    (CVE-2013-1862)

  - A flaw in the method by which the mod_dav module
    handles merge requests can allow an attacker to create
    a denial of service by sending a crafted merge request
    that contains URIs that are not configured for DAV.
    (CVE-2013-1896)

  - A flaw in PicketBox can allow local users to obtain the
    admin encryption key by reading the Vault data file.
    (CVE-2013-1921)

  - A flaw in Apache Santuario XML Security can allow
    context-dependent attackers to spoof an XML Signature
    by using the CanonicalizationMethod parameter to
    specify an arbitrary weak algorithm. (CVE-2013-2172)

  - A flaw in JGroup's DiagnosticsHandler can allow remote
    attackers to obtain sensitive information and execute
    arbitrary code by re-using valid credentials.
    (CVE-2013-4112)");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-3499.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4558.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-1862.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-1896.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-1921.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2172.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4112.html");

  script_set_attribute(attribute:"solution", value:
"Upgrade the installed JBoss Enterprise Application Platform 6.1.0 to
6.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");

info = "";
jboss = 0;
installs = get_kb_list_or_exit("Host/JBoss/EAP");
if(!isnull(installs)) jboss = 1;

foreach install (make_list(installs))
{
  match = eregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      info += '\n' + '  Path    : ' + path+ '\n';
      info += '  Version : ' + ver + '\n';
    }
  }
}

# Report what we found.
if (info)
{
  set_kb_item(name: 'www/0/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of the JBoss Enterprise Application Platform are';
    else s = ' of the JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be upgraded to 6.1.1 or later :\n' +
      info;

    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Enterprise Application Platform version installed is not affected.");
}
else audit(AUDIT_HOST_NOT, "affected");
