#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34119);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-3614", "CVE-2008-3615", "CVE-2008-3624", "CVE-2008-3625", "CVE-2008-3626",
                "CVE-2008-3627", "CVE-2008-3628", "CVE-2008-3629", "CVE-2008-3635");
  script_bugtraq_id(31086, 31546, 31548);
  script_osvdb_id(
    48027,
    48028,
    48029,
    48030,
    48031,
    48032,
    48033,
    48034,
    48038,
    48039,
    48040
  );

  script_name(english:"QuickTime < 7.5.5 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is older
than 7.5.5.  Such versions contain several vulnerabilities :

  - An integer overflow in QuickTime's handling of PICT
    images may lead to an application crash or arbitrary
    code execution (CVE-2008-3614).

  - An uninitialized memory access issue in the third-
    party Indeo v5 codec, which does not ship with
    QuickTime, may lead to an application crash or arbitrary
    code execution (CVE-2008-3615).

  - Heap and stack-based buffer overflows in the handling of
    panorama atoms in QTVR (QuickTime Virtual Reality)
    movie files could lead to an application crash or
    arbitrary code execution (CVE-2008-3624 and
    CVE-2008-3625).

  - A memory corruption issue in QuickTime's handling of
    STSZ atoms in movie files could lead to an
    application crash or arbitrary code execution
    (CVE-2008-3626).

  - Multiple memory corruption issues in QuickTime's
    handling of H.264-encoded movie files could lead to
    an application crash or arbitrary code execution
    (CVE-2008-3627).

  - An invalid pointer issue in QuickTime's handling of
    PICT images could lead to an application crash or
    arbitrary code execution (CVE-2008-3628).

  - An out-of-bounds read issue in QuickTime's handling
    of PICT images could lead to an application crash
    (CVE-2008-3629).

  - A stack-based buffer overflow exists in the third-party
    Indeo v3.2 codec for QuickTime, which could lead to an
    application crash or arbitrary code execution when
    viewing a specially crafted movie file (CVE-2008-3635)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3027" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.5.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 189, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/10");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");

ver_ui = get_kb_item("SMB/QuickTime/Version_UI");
ver = get_kb_item("SMB/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (
    iver[0] == 7 && 
    (
      iver[1] < 55 ||
      (
        iver[1] == 55 &&
        (
          iver[2] < 90 ||
          (iver[2] == 90 && iver[3] < 70)
        )
      )
    )
  )
)
{
  if (report_verbosity && ver_ui)
  {
    report = string(
      "\n",
      "QuickTime ", ver_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
