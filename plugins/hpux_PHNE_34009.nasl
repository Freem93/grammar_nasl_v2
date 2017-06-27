#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_34009. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22430);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2006-4820");
  script_osvdb_id(28828);
  script_xref(name:"HP", value:"emr_na-c00705202");
  script_xref(name:"HP", value:"HPSBUX02126");
  script_xref(name:"HP", value:"SSRT051019");

  script_name(english:"HP-UX PHNE_34009 : HP-UX running X.25 Local Denial of Service (Dos) (HPSBUX02126 SSRT051019 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 J2793B X.25 SX25-HPerf/SYNC-WAN : 

A potential security vulnerability has been identified with HP-UX
running X.25. The vulnerability could be exploited by a local user to
create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00705202
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c543af62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_34009 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHNE_34009 applies to a different OS release.");
}

patches = make_list("PHNE_34009");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-32ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.COM-64SLIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-32ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.IP-64ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-32ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.PA-64ALIB", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-COM", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-IP", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.21")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.22")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"7.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.0")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.25")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.26")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.27")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.28")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.29")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.30")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.31")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.33")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PA", version:"8.61")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.32")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.35")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.13")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.9")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.7.00.06")) flag++;
if (hpux_check_patch(app:"SX25-HPerf.SX25-SNMP", version:"A.11.00.ic23")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"3.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"4.0")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"5.15")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"5.3")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"5.6")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"5.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-32ALIB", version:"5.8")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"3.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"4.0")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"5.15")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"5.3")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"5.6")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"5.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-64ALIB", version:"5.8")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"3.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"4.0")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"5.15")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"5.3")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"5.6")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"5.7")) flag++;
if (hpux_check_patch(app:"SYNC-WAN.SYNC-COM", version:"5.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:hpux_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
