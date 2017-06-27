#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17781);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/14 13:43:45 $");
  
  script_cve_id("CVE-2004-0230");
  script_osvdb_id(4030);
  script_xref(name:"CISCO-BUG-ID", value:"CSCed27956");
  script_xref(name:"CISCO-BUG-ID", value:"CSCed93836");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20040420-tcp-ios");

  script_name(english:"TCP Vulnerabilities in Multiple IOS-Based Cisco Products");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is running a version of IOS that contains flaws in
the TCP implementation that can allow a remote attacker to reset any
established TCP connection."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?0f4830cc");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040420-tcp-ios."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/version");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

# Affected: 11.1
if (deprecated_version(version, "11.1")) 
{
  security_warning(port:0, extra:'\nMigrate to 11.2 latest version.\n'); 
  exit(0);
}

# Affected: 11.1AA
if (deprecated_version(version, "11.1AA")) 
{
  security_warning(port:0, extra:'\nMigrate to 11.2P latest version.\n'); 
  exit(0);
}

# Affected: 11.1CC
if (deprecated_version(version, "11.1CC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0 latest version.\n'); 
  exit(0);
}

# Affected: 11.2
if (check_release(version:version,
                  patched:make_list("11.2(26f)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 11.2P
if (check_release(version:version,
                  patched:make_list("11.2(26)P6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 11.2SA
if (check_release(version:version,
                  patched:make_list("11.2(8.12)SA6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 11.3
if (check_release(version:version,
                  patched:make_list("11.3(11b)T4", "11.3(11e)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.0
if (check_release(version:version,
                  patched:make_list("12.0(28)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2DA latest version.\n'); 
  exit(0);
}

# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1DB latest version.\n'); 
  exit(0);
}

# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1DC latest version.\n'); 
  exit(0);
}

# Affected: 12.0S
if (check_release(version:version,
                  patched:make_list("12.0(21)S8", "12.0(27)S", "12.0(26)S2", "12.0(16)S11", "12.0(24)S5", "12.0(25)S3", "12.0(23)S6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.0SL
if (deprecated_version(version, "12.0SL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0(23)S6 or later.\n'); 
  exit(0);
}

# Affected: 12.0ST
if (deprecated_version(version, "12.0ST")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0(26)S2 or later.\n'); 
  exit(0);
}

# Affected: 12.0SX
if (deprecated_version(version, "12.0SX")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.'); 
  exit(0);
}

# Affected: 12.0SZ
if (deprecated_version(version, "12.0SZ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0(26)S2 or later.\n'); 
  exit(0);
}

# Affected: 12.0T
if (deprecated_version(version, "12.0T")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0W5
if (check_release(version:version,
                  patched:make_list("12.0(25)W5(27b)", "12.0(28)W5(30)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.0WC
if (check_release(version:version,
                  patched:make_list("12.0(5)WC9a")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.0WT
if (deprecated_version(version, "12.0WT"))
{
  security_warning(port:0, extra:'\nNo fix available - End of Engineering\n'); 
  exit(0);
}

# Affected: 12.0WX
if (deprecated_version(version, "12.0WX")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0W5 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1E latest version.\n'); 
  exit(0);
}

# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XH
if (deprecated_version(version, "12.0XH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) 
{
  security_warning(port:0, extra:'\nUpdate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XK
if (deprecated_version(version, "12.0XK")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1T latest version.\n'); 
  exit(0);
}

# Affected: 12.0XL
if (deprecated_version(version, "12.0XL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected: 12.0XN
if (deprecated_version(version, "12.0XN")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XP
if (deprecated_version(version, "12.0XP")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0(5)WC9a or later.\n'); 
  exit(0);
}

# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected: 12.0XS
if (deprecated_version(version, "12.0XS")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1E latest version.\n'); 
  exit(0);
}

# Affected: 12.0XU
if (deprecated_version(version, "12.0XU")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.0(5)WC or later.\n'); 
  exit(0);
}

# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected: 12.1
if (check_release(version:version,
                  patched:make_list("12.1(20a)", "12.1(4c)", "12.1(22b)", "12.1(22c)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.1AA
if (deprecated_version(version, "12.1AA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected: 12.1AX
if (check_release(version:version,
                  patched:make_list("12.1(14)AX")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected: 12.1AY
if (deprecated_version(version, "12.1AY")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1EA latest version.\n'); 
  exit(0);
}

# Affected: 12.1DA
if (deprecated_version(version, "12.1DA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2DA latest version.\n'); 
  exit(0);
}

# Affected: 12.1DB
if (deprecated_version(version, "12.1DB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2B latest version.\n'); 
  exit(0);
}

# Affected 12.1E
if (check_release(version:version,
                  patched:make_list("12.1(19)E7", "12.1(22)E1", "12.1(11b)E14", "12.1(20)E2", "12.1(19)E6", "12.1(13)E13", "12.1(8b)E18", "12.1(14)E10", "12.1(13)E14")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EA
if (check_release(version:version,
                  patched:make_list("12.1(19)EA1b", "12.1(19)EA1c")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EB
if (check_release(version:version,
                  patched:make_list("12.1(20)EB")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EC
if (check_release(version:version,
                  patched:make_list("12.1(20)EC")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EO
if (check_release(version:version,
                  patched:make_list("12.1(20)EO", "12.1(19)EO2")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EU
if (check_release(version:version,
                  patched:make_list("12.1(20)EU")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EV
if (deprecated_version(version, "12.1EV")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(RLS4)S or later.\n'); 
  exit(0);
}

# Affected 12.1EW
if (check_release(version:version,
                  patched:make_list("12.1(20)EW2")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1EX
if (deprecated_version(version, "12.1EX")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1(14)E or later.\n'); 
  exit(0);
}

# Affected 12.1EY
if (deprecated_version(version, "12.1EY")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1(14)E or later.\n'); 
  exit(0);
}

# Affected 12.1T
if (check_release(version:version,
                  patched:make_list("12.1(5)T17")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.1XA
if (deprecated_version(version, "12.1XA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1(5)T18 or later.\n'); 
  exit(0);
}

# Affected 12.1XB
if (deprecated_version(version, "12.1XB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1XC
if (deprecated_version(version, "12.1XC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected 12.1XD
if (deprecated_version(version, "12.1XD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected 12.1XE
if (deprecated_version(version, "12.1XE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1E Lateest Version\n'); 
  exit(0);
}

# Affected 12.1XF
if (deprecated_version(version, "12.1XF")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1XG
if (deprecated_version(version, "12.1XG")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1XH
if (deprecated_version(version, "12.1XH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected 12.1XI
if (deprecated_version(version, "12.1XI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2 latest version.\n'); 
  exit(0);
}

# Affected 12.1XJ
if (deprecated_version(version, "12.1XJ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1XL
if (deprecated_version(version, "12.1XL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.1XM
if (deprecated_version(version, "12.1XM")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.1XP
if (deprecated_version(version, "12.1XP")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1XQ
if (deprecated_version(version, "12.1XQ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.1XR
if (deprecated_version(version, "12.1XR")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.1XT
if (deprecated_version(version, "12.1XT")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 latest version.\n'); 
  exit(0);
}

# Affected 12.1XU
if (deprecated_version(version, "12.1XU")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.1XV
if (deprecated_version(version, "12.1XV")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2XB latest version.\n'); 
  exit(0);
}

# Affected 12.1YA
if (deprecated_version(version, "12.1YA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(8)T or later.\n'); 
  exit(0);
}

# Affected 12.1YB
if (deprecated_version(version, "12.1YB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1YC
if (deprecated_version(version, "12.1YC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.1YD
if (deprecated_version(version, "12.1YD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(8)T or later.\n'); 
  exit(0);
}

# Affected 12.1YE
if (deprecated_version(version, "12.1YE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(2)YC or later.\n'); 
  exit(0);
}

# Affected 12.1YF
if (deprecated_version(version, "12.1YF")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(2)YC or later.\n'); 
  exit(0);
}

# Affected 12.1YH
if (deprecated_version(version, "12.1YH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)T or later.\n'); 
  exit(0);
}

# Affected 12.1YI
if (deprecated_version(version, "12.1YI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(2)YC or later.\n'); 
  exit(0);
}

# Affected 12.1YJ
if (deprecated_version(version, "12.1YJ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.1EA latest version.\n'); 
  exit(0);
}

# Affected 12.2
if (check_release(version:version,
                  patched:make_list("12.2(19b)", "12.2(16f)", "12.2(21a)", "12.2(23)", "12.2(12i)", "12.2(10g)", "12.2(13e)", "12.2(17d)", "12.2(21b)", "12.2(23a)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2B
if (deprecated_version(version, "12.2B")) 
{
  security_warning(port:0, 
  extra:'\nMigrate to 12.2(13)T12 / 12.3(5a)B1 or later.\n'); 
  exit(0);
}

# Affected 12.2BC
if (check_release(version:version,
                  patched:make_list("12.2(15)BC1C")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2BW
if (deprecated_version(version, "12.2BW")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2BX
if (check_release(version:version,
                  patched:make_list("12.2(16)BX3")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2BY
if (deprecated_version(version, "12.2BY")) 
{
  security_warning(port:0, 
  extra:'\nMigrate to 12.2(15)B / 12.2(8)ZB / 12.2(8)BZ or later.\n'); 
  exit(0);
}

# Affected 12.2BZ
if (deprecated_version(version, "12.2BZ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(16)BX or later.\n'); 
  exit(0);
}

# Affected 12.2CX
if (deprecated_version(version, "12.2CX")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)BC or later.\n'); 
  exit(0);
}

# Affected 12.2CY
if (deprecated_version(version, "12.2CY")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)BC1C or later.\n'); 
  exit(0);
}

# Affected 12.2DA
if (check_release(version:version,
                  patched:make_list("12.2(12)DA6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2DD
if (deprecated_version(version, "12.2DD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(4)B1 or later.\n'); 
  exit(0);
}

# Affected 12.2DX
if (deprecated_version(version, "12.2DX")) 
{
  security_warning(port:0, 
  extra:'\nMigrate to 12.2DD or 12.2B\n'); 
  exit(0);
}

# Affected 12.2EW
if (check_release(version:version,
                  patched:make_list("12.2(18)EW")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2JA
if (check_release(version:version,
                patched:make_list("12.2(11)JA3", "12.2(13)JA4", "12.2(15)JA")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2MC
if (check_release(version:version,
                  patched:make_list("12.2(15)MC1B")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2S
if (check_release(version:version,
                  patched:make_list("12.2(22)S", "12.2(14)S7", "12.2(20)S1", "12.2(20)S3", "12.2(18)S3")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SE
if (check_release(version:version,
                  patched:make_list("12.2(18)SE")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SW
if (check_release(version:version,
                  patched:make_list("12.2(21)SW")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SX
if (check_release(version:version,
                  patched:make_list("12.2(17a)SX2", "12.2(17a)SX4")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SXA
if (check_release(version:version,
                  patched:make_list("12.2(17b)SXA2")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SXB
if (check_release(version:version,
                  patched:make_list("12.2(17d)SXB1", "12.2(17d)SXB")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SY
if (check_release(version:version,
                  patched:make_list("12.2(14)SY3")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2SZ
if (check_release(version:version,
                  patched:make_list("12.2(14)SZ6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2ST
if (check_release(version:version,
                  patched:make_list("12.2(15)T11", "12.2(13)T12", "12.2(11)T11", "12.2(13)T11")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2XA
if (deprecated_version(version, "12.2XA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(11)T or later.\n'); 
  exit(0);
}

# Affected 12.2XB
if (deprecated_version(version, "12.2XB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3 latest version.\n'); 
  exit(0);
}

# Affected 12.2XC
if (deprecated_version(version, "12.2XC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(8)ZB or later.\n'); 
  exit(0);
}

# Affected 12.2XD
if (deprecated_version(version, "12.2XD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XE
if (deprecated_version(version, "12.2XE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XF
if (deprecated_version(version, "12.2XF")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(4)BC1C or later.\n'); 
  exit(0);
}

# Affected 12.2XG
if (deprecated_version(version, "12.2XG")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(8)T or later.\n'); 
  exit(0);
}

# Affected 12.2XH
if (deprecated_version(version, "12.2XH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XI
if (deprecated_version(version, "12.2XI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XJ
if (deprecated_version(version, "12.2XJ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XK
if (deprecated_version(version, "12.2XK")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XL
if (deprecated_version(version, "12.2XL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XM
if (deprecated_version(version, "12.2XM")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XN
if (deprecated_version(version, "12.2XN")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(11)T or later.\n'); 
  exit(0);
}

# Affected 12.2XQ
if (deprecated_version(version, "12.2XQ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XS
if (deprecated_version(version, "12.2XS")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(11)T or later.\n'); 
  exit(0);
}

# Affected 12.2XT
if (deprecated_version(version, "12.2XT")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(11)T or later.\n'); 
  exit(0);
}

# Affected 12.2XU
if (deprecated_version(version, "12.2XU")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2XW
if (deprecated_version(version, "12.2XW")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YA
if (deprecated_version(version, "12.2YA")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YB
if (deprecated_version(version, "12.2YB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YC
if (deprecated_version(version, "12.2YC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(11)T11 or later.\n'); 
  exit(0);
}

# Affected 12.2YD
if (deprecated_version(version, "12.2YD")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(8)YY or later.\n'); 
  exit(0);
}

# Affected 12.2YE
if (deprecated_version(version, "12.2YE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2S latest version.\n'); 
  exit(0);
}

# Affected 12.2YF
if (deprecated_version(version, "12.2YF")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YG
if (deprecated_version(version, "12.2YG")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YH
if (deprecated_version(version, "12.2YH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YJ
if (deprecated_version(version, "12.2YJ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T12 or later.\n'); 
  exit(0);
}

# Affected 12.2YK
if (deprecated_version(version, "12.2YK")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(13)ZC or later.\n'); 
  exit(0);
}

# Affected 12.2YL
if (deprecated_version(version, "12.2YL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YM
if (deprecated_version(version, "12.2YM")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YN
if (deprecated_version(version, "12.2YN")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YO
if (deprecated_version(version, "12.2YO")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(14)SY or later.\n'); 
  exit(0);
}

# Affected 12.2YP
if (deprecated_version(version, "12.2YP")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2T latest version.\n'); 
  exit(0);
}

# Affected 12.2YQ
if (deprecated_version(version, "12.2YQ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YR
if (deprecated_version(version, "12.2YR")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YS
if (deprecated_version(version, "12.2YS")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.2YT
if (deprecated_version(version, "12.2YT")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(15)T or later.\n'); 
  exit(0);
}

# Affected 12.2YU
if (deprecated_version(version, "12.2YU")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YV
if (deprecated_version(version, "12.2YV")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(4)T or later.\n'); 
  exit(0);
}

# Affected 12.2YW
if (deprecated_version(version, "12.2YW")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2YX
if (deprecated_version(version, "12.2YX")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(RLS3)S or later.\n'); 
  exit(0);
}

# Affected 12.2YY
if (deprecated_version(version, "12.2YY")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(1)T or later.\n'); 
  exit(0);
}

# Affected 12.2YZ
if (deprecated_version(version, "12.2YZ")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(14)SZ or later.\n'); 
  exit(0);
}

# Affected 12.2ZA
if (check_release(version:version, patched:make_list("12.2(14)ZA6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2ZB
if (deprecated_version(version, "12.2ZB")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.2ZC
if (deprecated_version(version, "12.2ZC")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.2ZD
if (check_release(version:version, patched:make_list("12.2(13)ZD1")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2ZE
if (deprecated_version(version, "12.2ZE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3 latest version.\n'); 
  exit(0);
}

# Affected 12.2ZF
if (deprecated_version(version, "12.2ZF")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(4)T or later.\n'); 
  exit(0);
}

# Affected 12.2ZG
if (deprecated_version(version, "12.2ZG")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(4)T or later.\n'); 
  exit(0);
}

# Affected 12.2ZH
if (deprecated_version(version, "12.2ZH")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(4)T or later.\n'); 
  exit(0);
}

# Affected 12.2ZI
if (deprecated_version(version, "12.2ZI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.2(18)S or later.\n'); 
  exit(0);
}

#Affected 12.2ZJ
if (check_release(version:version, 
                  patched:make_list("12.2(15)ZJ5", "12.2(15)ZJ4")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.2ZK
if (deprecated_version(version, "12.2ZK")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.2ZL
if (deprecated_version(version, "12.2ZL")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(7)T or later.\n'); 
  exit(0);
}

# Affected 12.2ZN
if (deprecated_version(version, "12.2ZN")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3(2)T or later.\n'); 
  exit(0);
}

# Affected 12.2ZP
if (check_release(version:version, patched:make_list("12.2(13)ZP3")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3
if (check_release(version:version, 
                  patched:make_list("12.3(3e)", "12.3(6)", "12.3(5b)")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}


# Affected 12.3B
if (check_release(version:version, 
                  patched:make_list("12.3(5a)B", "12.3(3)B1")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3BW
if (deprecated_version(version, "12.3BW")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3B latest version.\n'); 
  exit(0);
}

# Affected 12.3T
if (check_release(version:version, 
                  patched:make_list("12.3(2)T4", "12.3(7)T1", "12.3(4)T3", "12.3(4)T6")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XA
if (deprecated_version(version, "12.3XA")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XB
if (check_release(version:version, patched:make_list("12.3(2)XB2")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XC
if (check_release(version:version, patched:make_list("12.3(2)XC2")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XD
if (check_release(version:version, patched:make_list("12.3(4)XD1")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XE
if (deprecated_version(version, "12.3XE")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.3XF
if (deprecated_version(version, "12.3XF")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XG
if (check_release(version:version, patched:make_list("12.3(4)XG")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XH
if (check_release(version:version, patched:make_list("12.3(4)XH")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XI
if (deprecated_version(version, "12.3XI")) 
{
  security_warning(port:0, extra:'\nMigrate to 12.3T latest version.\n'); 
  exit(0);
}

# Affected 12.3XJ
if (deprecated_version(version, "12.3XJ")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XK
if (check_release(version:version, patched:make_list("12.3(4)XK")))
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}

# Affected 12.3XL
if (deprecated_version(version, "12.3XL")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XM
if (deprecated_version(version, "12.3XM")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XN
if (deprecated_version(version, "12.3XN")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

# Affected 12.3XQ
if (deprecated_version(version, "12.3XQ")) 
{
  security_warning(port:0, extra:'\nContact Cisco TAC for fix information.\n'); 
  exit(0);
}

exit(0, "The host is not affected.");
