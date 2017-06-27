#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1784. The text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71900);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/06 19:05:27 $");

  script_cve_id("CVE-2013-2035", "CVE-2013-2133");
  script_bugtraq_id(59876, 64125);
  script_osvdb_id(93411, 100657);
  script_xref(name:"RHSA", value:"2013:1784");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2013:1784)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for Red Hat JBoss Enterprise Application Platform 6.2.0,
which fixes two security issues, several bugs, and adds various
enhancements, is now available from the Red Hat Customer Portal.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

The HawtJNI Library class wrote native libraries to a predictable file
name in /tmp/ when the native libraries were bundled in a JAR file,
and no custom library path was specified. A local attacker could
overwrite these native libraries with malicious versions during the
window between when HawtJNI writes them and when they are executed.
(CVE-2013-2035)

A flaw was found in the way method-level authorization for JAX-WS
Service endpoints was performed by the EJB invocation handler
implementation. Any restrictions declared on EJB methods were ignored
when executing the JAX-WS handlers, and only class-level restrictions
were applied. A remote attacker who is authorized to access the EJB
class, could invoke a JAX-WS handler which they were not authorized to
invoke. (CVE-2013-2133)

The CVE-2013-2035 issue was discovered by Florian Weimer of the Red
Hat Product Security Team, and the CVE-2013-2133 issue was discovered
by Richard Opalka and Arun Neelicattu of Red Hat.

This release serves as a replacement for JBoss Enterprise Application
Platform 6.1.1, and includes bug fixes and enhancements. Documentation
for these changes will be available shortly from the JBoss Enterprise
Application Platform 6.2.0 Release Notes, linked to in the References.

All users of Red Hat JBoss Enterprise Application Platform 6.2.0 as
provided from the Red Hat Customer Portal are advised to apply this
update. The JBoss server process must be restarted for the update to
take effect.

This plugin does not check for JBoss installs on the following remote
filesystem types: NFS, AFS, SMBFS, CIFS.");

  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2035.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2133.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2013-1784.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to JBoss Enterprise Application Platform 6.2.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.2.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("jboss_detect.nbin");
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
  match = eregmatch(string:install, pattern:"([0-9\.]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    # check for install version < 6.2.0
    if (ver_compare(ver:ver, fix:"6.2.0") < 0)
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
    if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
    else s = ' of JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
      info;

    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Portal Platform version installed is not affected.");
}
else audit(AUDIT_HOST_NOT, "affected");
