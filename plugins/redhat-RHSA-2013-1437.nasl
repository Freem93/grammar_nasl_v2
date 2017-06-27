#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72237);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 20:36:57 $");

  script_cve_id(
    "CVE-2012-4431",
    "CVE-2012-4529",
    "CVE-2012-4572",
    "CVE-2012-5575",
    "CVE-2013-1921",
    "CVE-2013-2067",
    "CVE-2013-2102",
    "CVE-2013-2160",
    "CVE-2013-2172",
    "CVE-2013-4112",
    "CVE-2013-4128",
    "CVE-2013-4213"
  );
  script_bugtraq_id(
    56814,
    59799,
    60040,
    60043,
    60045,
    60846,
    61030,
    61179,
    61739,
    61742,
    62256,
    63196
  );
  script_osvdb_id(
    88093,
    93252,
    93462,
    93543,
    93545,
    94651,
    95011,
    95386,
    96216,
    96217,
    96980,
    98633
  );
  script_xref(name:"RHSA", value:"2013:1437");

  script_name(english:"JBoss Portal 6.1.0 Update (RHSA-2013:1437)");
  script_summary(english:"Checks for the install versions of JBoss Portal");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Portal Platform on the remote system is
affected by the following issues:

  - A flaw in CSRF prevention filter in JBoss Web could allow
    remote attackers to bypass the cross-site request forgery
    (CSRF) protection mechanism via a request that lacks a
    session identifier. (CVE-2012-4431)

  - A flaw that occurs when the COOKIE session tracking
    method is used can allow attackers to hijack users'
    sessions. (CVE-2012-4529)

  - A flaw that occurs when multiple applications use the
    same custom authorization module class name can allow a
    local attacker to deploy a malicious application that
    overrides the custom authorization modules provided by
    other applications. (CVE-2012-4572)

  - The framework does not verify that a specified
    cryptographic algorithm is allowed by the
    WS-SecurityPolicy AlgorithmSuite definition before
    decrypting.  This can allow remote attackers to force
    the system to use weaker cryptographic algorithms than
    intended and makes it easier to decrypt communications.
    (CVE-2012-5575)

  - A flaw in PicketBox can allow local users to obtain the
    admin encryption key by reading the Vault data file.
    (CVE-2013-1921)

  - A session fixation flaw was found in the
    FormAuthenticator module. (CVE-2013-2067)

  - A flaw that occurs when a JGroups channel was started
    results in the JGroups diagnostics service being enabled
    by default with no authentication via IP multicast. A
    remote attacker can make use of this flaw to read
    diagnostics information. (CVE-2013-2102)

  - A flaw in the StAX parser implementation can allow
    remote attackers to cause a denial of service via
    crafted XML. (CVE-2013-2160)

  - A flaw in Apache Santuario XML Security can allow
    context-dependent attackers to spoof an XML Signature
    by using the CanonicalizationMethod parameter to
    specify an arbitrary weak algorithm. (CVE-2013-2172)

  - A flaw in JGroup's DiagnosticsHandler can allow remote
    attackers to obtain sensitive information and execute
    arbitrary code by re-using valid credentials.
    (CVE-2013-4112)

  - A flaw in the manner in which authenticated connections
    were cached on the server by remote-naming can allow
    remote attackers to hijack sessions by using a remoting
    client. (CVE-2013-4128)

  - A flaw in the manner in which connections for EJB
    invocations were cached on the server can allow remote
    attackers to hijack sessions by using an EJB client.
    (CVE-2013-4213)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=868202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=872059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=880443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=883636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=929197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=948106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=961779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=963984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=983489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=984795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=985359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=999263");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4431.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4529.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-4572.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2012-5575.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-1921.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2067.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2102.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2160.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2172.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4112.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4128.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4213.html");

  script_set_attribute(attribute:"solution", value:
"Upgrade the installed JBoss Portal 6.0.0 to 6.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_portal_platform:6.1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
installs = get_kb_list_or_exit("Host/JBoss/Portal Platform");
if(!isnull(installs)) jboss = 1;

foreach install (make_list(installs))
{
  match = eregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    if (ver =~ "^6.0.0([^0-9]|$)")
    {
      info += '\n' + '  Path    : ' + path+ '\n';
      info += '  Version : ' + ver + '\n';
    }
  }
}

# Report what we found.
if (info)
{
  set_kb_item(name:"www/0/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Portal Platform are';
    else s = ' of JBoss Enterprise Portal Platform is';

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
  exit(0, "The JBoss Enterprise Portal Platform version installed is not affected.");
}
else audit(AUDIT_HOST_NOT, "affected");
