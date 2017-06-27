#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68962);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/07/19 02:36:28 $");

  script_cve_id("CVE-2010-0451");
  script_bugtraq_id(38982);
  script_osvdb_id(63243);
  script_xref(name:"HP", value:"emr_na-c02026642");
  script_xref(name:"IAVB", value:"2010-B-0026");
  script_xref(name:"HP", value:"HPSBUX02509");
  script_xref(name:"HP", value:"SSRT100032");

  script_name(english:"HP-UX Running NFS/ONCplus, NFS Inadvertently Enabled (HPSBUX02509 SSRT100032 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(attribute:"synopsis", value:"The remote HP-UX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote HP-UX system is affected by a security bypass vulnerability
in NFS/ONCplus.  This issue could enable the NFS_SERVER setting in the
nfsconf file, which might allow attackers to obtain filesystem access
via NFS requests.");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02026642
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5458ab0");
  script_set_attribute(attribute:"solution", value:"Upgrade to ONCplus_B.11.31.09.depot or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/25");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("hpux.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since this vulnerability applies to a different OS release.");
}

flag = 0;

if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64ALIB", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CLIENT", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CORE", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SERVER", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CLIENT", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CORE", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-PRG", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-SERVER", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CLIENT", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CORE", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS-SERVER", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CLIENT", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CORE", version:"B.11.31.09")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-SERVER", version:"B.11.31.09")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
