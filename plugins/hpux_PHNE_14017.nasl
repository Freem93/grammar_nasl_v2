#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_14017. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16850);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:32:52 $");

  script_cve_id("CVE-1999-0016");
  script_xref(name:"HP", value:"HPSBUX9801-076");

  script_name(english:"HP-UX PHNE_14017 : s700_800 11.00 cumulative ARPA Transport patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 cumulative ARPA Transport patch : 

A TCP SYN packet with target host's address as both source and
destination can cause system hangs."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_14017 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"1998/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_14017 applies to a different OS release.");
}

patches = make_list("PHNE_14017", "PHNE_14279", "PHNE_14702", "PHNE_15047", "PHNE_15583", "PHNE_15692", "PHNE_15995", "PHNE_16283", "PHNE_16645", "PHNE_17017", "PHNE_17446", "PHNE_17662", "PHNE_18554", "PHNE_18611", "PHNE_18708", "PHNE_19110", "PHNE_19375", "PHNE_19899", "PHNE_20436", "PHNE_20735", "PHNE_21767", "PHNE_22397", "PHNE_23456", "PHNE_24715", "PHNE_25423", "PHNE_26771", "PHNE_27886", "PHNE_28538", "PHNE_29473", "PHNE_32041", "PHNE_33395", "PHNE_35729");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
