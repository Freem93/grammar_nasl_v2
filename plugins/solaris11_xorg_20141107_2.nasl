#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80823);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:24:31 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");

  script_name(english:"Oracle Solaris Third-Party Patch Update : xorg (multiple_vulnerabilities_in_x_org2)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Multiple integer overflows in the (1) FontFileAddEntry
    and (2) lexAlias functions in X.Org libXfont before
    1.4.8 and 1.4.9x before 1.4.99.901 might allow local
    users to gain privileges by adding a directory with a
    large fonts.dir or fonts.alias file to the font path,
    which triggers a heap-based buffer overflow, related to
    metadata. (CVE-2014-0209)

  - Multiple buffer overflows in X.Org libXfont before 1.4.8
    and 1.4.9x before 1.4.99.901 allow remote font servers
    to execute arbitrary code via a crafted xfs protocol
    reply to the (1) _fs_recv_conn_setup, (2)
    fs_read_open_font, (3) fs_read_query_info, (4)
    fs_read_extent_info, (5) fs_read_glyphs, (6)
    fs_read_list, or (7) fs_read_list_info function.
    (CVE-2014-0210)

  - Multiple integer overflows in the (1) fs_get_reply, (2)
    fs_alloc_glyphs, and (3) fs_read_extent_info functions
    in X.Org libXfont before 1.4.8 and 1.4.9x before
    1.4.99.901 allow remote font servers to execute
    arbitrary code via a crafted xfs reply, which triggers a
    buffer overflow. (CVE-2014-0211)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_x_org2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb0925c5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.21.4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:xorg");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^xorg$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.21.0.4.1", sru:"SRU 11.1.21.4.1") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : xorg\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "xorg");
