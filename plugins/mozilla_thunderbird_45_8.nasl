#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97663);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/16 14:21:22 $");

  script_cve_id(
    "CVE-2017-5398",
    "CVE-2017-5400",
    "CVE-2017-5401",
    "CVE-2017-5402",
    "CVE-2017-5404",
    "CVE-2017-5405",
    "CVE-2017-5407",
    "CVE-2017-5408",
    "CVE-2017-5410"
  );
  script_bugtraq_id(
    96651,
    96654,
    96664,
    96677,
    96693
  );
  script_osvdb_id(
    153143,
    153173,
    153174,
    153175,
    153176,
    153177,
    153178,
    153179,
    153180,
    153181,
    153182,
    153183,
    153190,
    153191,
    153192,
    153193,
    153195,
    153198,
    153214
  );
  script_xref(name:"MFSA", value:"2017-07");

  script_name(english:"Mozilla Thunderbird < 45.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote Windows
host is prior to 45.8. It is, therefore, affected by multiple
vulnerabilities :

  - Mozilla developers and community members Boris Zbarsky,
    Christian Holler, Honza Bambas, Jon Coppeard, Randell
    Jesup, Andre Bargull, Kan-Ru Chen, and Nathan Froyd
    reported memory safety bugs present in Thunderbird
    45.7. Some of these bugs showed evidence of memory
    corruption, and we presume that with enough effort that
    some of these could be exploited to run arbitrary code.
    (CVE-2017-5398)

  - JIT-spray targeting asm.js combined with a heap spray
    allows for a bypass of ASLR and DEP protections leading
    to potential memory corruption attacks. (CVE-2017-5400)

  - A crash triggerable by web content in which an
    ErrorResult references unassigned memory due to a logic
    error. The resulting crash may be exploitable.
    (CVE-2017-5401)

  - A use-after-free can occur when events are fired for a
    FontFace object after the object has been already been
    destroyed while working with fonts. This results in a
    potentially exploitable crash. (CVE-2017-5402)

  - A use-after-free error can occur when manipulating
    ranges in selections with one node inside a native
    anonymous tree and one node outside of it. This results
    in a potentially exploitable crash. (CVE-2017-5404)

  - Certain response codes in FTP connections can result in
    the use of uninitialized values for ports in FTP
    operations. (CVE-2017-5405)

  - Using SVG filters that don't use the fixed point math
    implementation on a target iframe, a malicious page can
    extract pixel values from a targeted user. This can be
    used to extract history information and read text
    values across domains. This violates same-origin policy
    and leads to information disclosure. (CVE-2017-5407)

  - Video files loaded video captions cross-origin without
    checking for the presence of CORS headers permitting
    such cross-origin use, leading to potential information
    disclosure for video captions. (CVE-2017-5408)

  - Memory corruption resulting in a potentially
    exploitable crash during garbage collection of
    JavaScript due to errors in how incremental sweeping is
    managed for memory cleanup. (CVE-2017-5410)

Note that Tenable Network Security has extracted the preceding
description block directly from the Mozilla security advisories.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-07/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1313711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1324379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1330687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1332550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1332597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1333568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1333887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1334876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1334933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1335450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1338383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1340138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 45.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', fix:'45.8', severity:SECURITY_HOLE);
