#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(73908);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id("CVE-2013-4239", "CVE-2014-4239");
  script_bugtraq_id(68631);
  script_osvdb_id(109104);

  script_name(english:"Solaris 10 (sparc) : 123893-81");
  script_summary(english:"Check for patch 123893-81");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 123893-81"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Enterprise Manager
Grid Control (subcomponent: Common Agent Container (Cacao)). Supported
versions that are affected are 2.3.1.0, 2.3.1.1, 2.3.1.2, 2.4.0.0,
2.4.1.0 and 2.4.2.0. Easily exploitable vulnerability allows
successful authenticated network attacks via SSL/TLS. Successful
attack of this vulnerability can result in unauthorized read access to
a subset of Solaris accessible data. Note: Applies only when Cacao is
running on Solaris platform.

Vulnerability in the Solaris component of Oracle Enterprise Manager
Grid Control (subcomponent: Common Agent Container (Cacao)). Supported
versions that are affected are 2.3.1.0, 2.3.1.1, 2.3.1.2, 2.4.0.0,
2.4.1.0 and 2.4.2.0. Easily exploitable vulnerability allows
successful authenticated network attacks via SSL/TLS. Successful
attack of this vulnerability can result in unauthorized read access to
a subset of Solaris accessible data. Note: Applies only when Cacao is
running on Solaris platform.

Vulnerability in the Solaris component of Oracle Enterprise Manager
Grid Control (subcomponent: Common Agent Container (Cacao)). Supported
versions that are affected are 2.3.1.0, 2.3.1.1, 2.3.1.2, 2.4.0.0,
2.4.1.0 and 2.4.2.0. Easily exploitable vulnerability allows
successful authenticated network attacks via SSL/TLS. Successful
attack of this vulnerability can result in unauthorized read access to
a subset of Solaris accessible data. Note: Applies only when Cacao is
running on Solaris platform."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/123893-81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123893-81", obsoleted_by:"", package:"SUNWcacaort", version:"2.0,REV=15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
