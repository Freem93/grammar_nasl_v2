#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2014.
#
include("compat.inc");

if (description)
{
  script_id(76821);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2014-4239");
  script_bugtraq_id(68631);
  script_osvdb_id(109104);

  script_name(english:"Oracle Solaris Critical Patch Update : jul2014_SRU11_1_19_6_0");
  script_summary(english:"Check for the jul2014 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
jul2014."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle
    Enterprise Manager Grid Control (subcomponent: Common
    Agent Container (Cacao)). Supported versions that are
    affected are 2.3.1.0, 2.3.1.1, 2.3.1.2, 2.4.0.0, 2.4.1.0
    and 2.4.2.0. Easily exploitable vulnerability allows
    successful authenticated network attacks via SSL/TLS.
    Successful attack of this vulnerability can result in
    unauthorized read access to a subset of Solaris
    accessible data. Note: Applies only when Cacao is
    running on Solaris platform. (CVE-2014-4239)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2225373.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1be6d29"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7de2f8eb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1900373.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the jul2014 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


fix_release = "0.5.11-0.175.1.19.0.6.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.19.0.6.0", sru:"11.1.19.6.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
