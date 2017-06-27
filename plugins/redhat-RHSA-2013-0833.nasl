#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66971);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/02 20:36:57 $");

  script_cve_id(
    "CVE-2012-4529",
    "CVE-2012-4572",
    "CVE-2012-5575",
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2013-0218",
    "CVE-2013-2067"
  );
  script_bugtraq_id(57652, 57778, 59799, 60040, 60043, 60045, 60268);
  script_osvdb_id(89698, 89865, 89848, 93252, 93462, 93543, 93545);
  script_xref(name:"RHSA", value:"2013:0833");

  script_name(english:"JBoss Enterprise Application Platform 6.1.0 Update (RHSA-2013:0833)");
  script_summary(english:"Checks for the installed versions of JBoss Enterprise Application Platform");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform 6.0.1 running on
the remote system is vulnerable to the following issues:

  - A man-in-the-middle attack is possible when applications
    running on JBoss Web use the COOKIE session tracking
    method. The flaw is in the
    org.apache.catalina.connector.Response.encodeURL()
    method. By making use of this, an attacker could obtain
    a user's jsessionid and hijack their session.
    (CVE-2012-4529)

  - If multiple applications used the same custom
    authorization module class name, a local attacker could
    deploy a malicious application authorization module that
    would permit or deny user access. (CVE-2012-4572)

  - XML encryption backwards compatibility attacks could
    allow an attacker to force a server to use insecure
    legacy cryptosystems. (CVE-2012-5575)

  - A NULL pointer dereference flaw could allow a malicious
    OCSP to crash applications performing OCSP verification.
    (CVE-2013-0166)

  - An OpenSSL leaks timing information issue exists that
    could allow a remote attacker to retrieve plaintext
    from the encrypted packets. (CVE-2013-0169)

  - The JBoss Enterprise Application Platform administrator
    password and the sucker password are stored in a world-
    readable, auto-install XML file created by the GUI
    installer. (CVE-2013-0218)

  - Tomcat incorrectly handles certain authentication
    requests. A remote attacker could use this flaw to
    inject a request that would get executed with a victim's
    credentials. (CVE-2013-2067)");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4529.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4572.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-5575.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-0166.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-0169.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-0218.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2067.html");
  # https://access.redhat.com/jbossnetwork/restricted/listSoftware.html?product=appplatform&downloadType=distributions
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7770d98");
  script_set_attribute(attribute:"solution", value:
"Upgrade the installed JBoss Enterprise Application Platform 6.0.1 to
6.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.0.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

    if (ver =~ "^6.0.1([^0-9]|$)")
    {
      info += '\n' + '  Path    : ' + path+ '\n';
      info += '  Version : ' + ver + '\n';
    }
  }
}

# Report what we found.
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of the JBoss Enterprise Application Platform are';
    else s = ' of the JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be upgraded to 6.1.0 or later :\n' +
      info;

    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Enterprise Application Platform version installed is not affected.");
}
else audit(AUDIT_HOST_NOT, "affected");

