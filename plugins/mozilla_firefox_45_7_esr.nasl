#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96775);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id(
    "CVE-2017-5373",
    "CVE-2017-5375",
    "CVE-2017-5376",
    "CVE-2017-5378",
    "CVE-2017-5380",
    "CVE-2017-5383",
    "CVE-2017-5386",
    "CVE-2017-5390",
    "CVE-2017-5396"
  );
  script_bugtraq_id(
    95757,
    95758,
    95762,
    95769
  );
  script_osvdb_id(
    150831,
    150832,
    150834,
    150836,
    150837,
    150858,
    150859,
    150860,
    150861,
    150862,
    150863,
    150864,
    150865,
    150866,
    150875,
    150878,
    150881
  );
  script_xref(name:"MFSA", value:"2017-02");

  script_name(english:"Mozilla Firefox ESR < 45.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is prior to 45.7. It is, therefore, affected by multiple
vulnerabilities :

  - Mozilla developers and community members Christian
    Holler, Gary Kwong, Andre Bargull, Jan de Mooij, Tom
    Schuster, and Oriol reported memory safety bugs present
    in Firefox 50.1 and Firefox ESR 45.6. Some of these
    bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these
    could be exploited to run arbitrary code.
    (CVE-2017-5373)

  - JIT code allocation can allow for a bypass of ASLR and
    DEP protections leading to potential memory corruption
    attacks. (CVE-2017-5375)

  - Use-after-free while manipulating XSL in XSLT documents
    (CVE-2017-5376)

  - Hashed codes of JavaScript objects are shared between
    pages. This allows for pointer leaks because an object's
    address can be discovered through hash codes, and also
    allows for data leakage of an object's content using
    these hash codes. (CVE-2017-5378)

  - A potential use-after-free found through fuzzing during
    DOM manipulation of SVG content. (CVE-2017-5380)

  - URLs containing certain unicode glyphs for alternative
    hyphens and quotes do not properly trigger punycode
    display, allowing for domain name spoofing attacks in
    the location bar. (CVE-2017-5383)

  - WebExtension scripts can use the 'data:' protocol to
    affect pages loaded by other web extensions using this
    protocol, leading to potential data disclosure or
    privilege escalation in affected extensions.
    (CVE-2017-5386)

  - The JSON viewer in the Developer Tools uses insecure
    methods to create a communication channel for copying
    and viewing JSON or HTTP headers data, allowing for
    potential privilege escalation. (CVE-2017-5390)

  - A use-after-free vulnerability in the Media Decoder
    when working with media files when some events are
    fired after the media elements are freed from memory.
    (CVE-2017-5396)

Note that Tenable Network Security has extracted the preceding
description block directly from the Mozilla security advisories.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1285833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1285960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1297361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1311687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1312001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1319070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1323338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1324716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1329403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1330769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1331058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 45.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.7', severity:SECURITY_HOLE);
