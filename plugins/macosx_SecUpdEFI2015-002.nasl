#TRUSTED 3cbf4420f14cca57cdec168202dc76883ab4b76946db5edd75997aa4ab36d1e60b1083585decc265bd31e2e44883191d237a1bb7e218ea9005c14e1bf00e6bb41a8948ebaf4c8a4c596baf3c54a8481481ebc70c5bcba82da76929aa836ece2033f5b9a6700ca4cbdeb33cdf4eecd757b86fc9c3a888d0af8b97b93a132374df07fd53a40f36208ed4fe39082420c7da926e9e76d85bb40379168e568fdfbf9aeeb77f146bf20f6fbf3f27fb1afe251cef0835591b40a66b0905e55a8cf0ae7c87b90e978500c62b033d95dc199b1cb4cdfc19649face2a1136f6c9902767c43a63023706035461097e3effc7a9fda31d42cd3dd32693e9d6ba69403b0413203955847af9f02084347c8e4f0832f4cae7a64a5e7a39d3e21a2bb464b22a6b8883fa88e4b7b8edf69f715c72fe93f1c67a5d5978e02bb4f43c410a4bbf1d1e903b2fdc5f1bcd546059591b4fac0e16370d915444b667b1b33f2de08a8815dd075a52582aa5b68a88e8e04d53df373700f8e7e06e613bb24cc7be87d1628a587ea39d8a128d6f53030e2b3574b2f0331feae7c4907f3956561eb3ab57307005c97fb4b5af7d4d60f76b764a05f8ff4be53dfbd9f10d0803f36bc3b95846b24d146920979a3090ecfeadf5103a62c17634aa58ac8b02a1b76baf25f2558704a3ccac19bb6e96c6bb5c0667c1a9223982ef0ec657ff68f08e66fb1604729f68ad2fd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86722);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/04");

  script_cve_id("CVE-2015-7035");
  script_bugtraq_id(74971);
  script_osvdb_id(129224);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-6");

  script_name(english:"Mac OS X EFI Function Execution Vulnerability (EFI Security Update 2015-002)");
  script_summary(english:"Checks the EFI version.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by a function execution vulnerability.");
  script_set_attribute(attribute:"description",value:
"The remote Mac OS X host is running an EFI firmware version that is
affected by a function execution vulnerability due to an issue with
handling EFI arguments. An unauthenticated, remote attacker can
exploit this to execute arbitrary functions via unspecified vectors.");
  script_set_attribute(attribute:"see_also",value:"https://support.apple.com/en-us/HT205317");
  # https://lists.apple.com/archives/security-announce/2015/Oct/msg00007.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?df1789d1");
  script_set_attribute(attribute:"solution",value:
"Install Mac EFI Security Update 2015-002.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/04");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("byte_func.inc");

efi_fixes = make_nested_array(
  "Mac-942459F5819B171B",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-FC02E91DDD3FA6A4",
  make_array(
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-3CBD00234E554E41",
  make_array(
    "efi-version", "MBP112.88Z.0138.B16.1509081314"
  ),
  "Mac-8ED6AF5B48C039E1",
  make_array(
    "efi-version", "MM51.88Z.0077.B12.1506081728"
  ),
  "Mac-35C1E88140C3E6CF",
  make_array(
    "efi-version", "MBA61.88Z.0099.B20.1509081314",
    "minimum-smc-version", "2.12f135"
  ),
  "Mac-F2268DAE",
  make_array(
    "efi-version", "IM111.88Z.0034.B04.1509231906"
  ),
  "Mac-81E3E92DD6088272",
  make_array(
    "efi-version", "IM144.88Z.0179.B12.1509081439"
  ),
  "Mac-94245BF5819B151B",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-4BC72D62AD45599E",
  make_array(
    "efi-version", "MM51.88Z.0077.B12.1506081728"
  ),
  "Mac-2E6FAB96566FE58C",
  make_array(
    "efi-version", "MBA51.88Z.00EF.B04.1509111654"
  ),
  "Mac-031AEE4D24BFF0B1",
  make_array(
    "efi-version", "MM61.88Z.0106.B0A.1509111654"
  ),
  "Mac-7BA5B2794B2CDB12",
  make_array(
    "efi-version", "MM51.88Z.0077.B12.1506081728"
  ),
  "Mac-7DF2A3B5E5D671ED",
  make_array(
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-00BE6ED71E35EB86",
  make_array(
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-F2238AC8",
  make_array(
    "efi-version", "IM112.88Z.0057.B03.1509231647"
  ),
  "Mac-742912EFDBEE19B3",
  make_array(
    "efi-version", "MBA41.88Z.0077.B12.1506081728"
  ),
  "Mac-942B59F58194171B",
  make_array(
    "efi-version", "IM121.88Z.0047.B21.1506101610"
  ),
  "Mac-189A3D4F975D5FFC",
  make_array(
    "efi-version", "MBP111.88Z.0138.B16.1509081438"
  ),
  "Mac-F22586C8",
  make_array(
    "efi-version", "MBP61.88Z.0057.B11.1509232013"
  ),
  "Mac-4B7AC7E43945597E",
  make_array(
    "efi-version", "MBP91.88Z.00D3.B0C.1509111653"
  ),
  "Mac-F22589C8",
  make_array(
    "efi-version", "MBP61.88Z.0057.B11.1509232013"
  ),
  "Mac-C3EC7CD22292981F",
  make_array(
    "efi-version", "MBP101.88Z.00EE.B0A.1509111559"
  ),
  "Mac-7DF21CB3ED6977E5",
  make_array(
    "efi-version", "MBA61.88Z.0099.B20.1509081314",
    "minimum-smc-version", "2.13f7"
  ),
  "Mac-942B5BF58194151B",
  make_array(
    "efi-version", "IM121.88Z.0047.B21.1506101610"
  ),
  "Mac-94245B3640C91C81",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-6F01561E16C75D06",
  make_array(
    "efi-version", "MBP91.88Z.00D3.B0C.1509111653"
  ),
  "Mac-94245A3940C91C80",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-27ADBB7B4CEE8E61",
  make_array(
    "efi-version", "IM142.88Z.0118.B12.1509081435"
  ),
  "Mac-031B6874CF7F642A",
  make_array(
    "efi-version", "IM141.88Z.0118.B12.1509081313"
  ),
  "Mac-F60DEB81FF30ACF6",
  make_array(
    "efi-version", "MP61.88Z.0116.B16.1509081436"
  ),
  "Mac-77EB7D7DAF985301",
  make_array(
    "efi-version", "IM143.88Z.0118.B12.1509081435"
  ),
  "Mac-F2238BAE",
  make_array(
    "efi-version", "IM112.88Z.0057.B03.1509231647"
  ),
  "Mac-F65AE981FFA204ED",
  make_array(
    "efi-version", "MM61.88Z.0106.B0A.1509111654"
  ),
  "Mac-C08A6BB70A942AC2",
  make_array(
    "efi-version", "MBA41.88Z.0077.B12.1506081728"
  ),
  "Mac-66F35F19FE2A0D05",
  make_array(
    "efi-version", "MBA51.88Z.00EF.B04.1509111654"
  ),
  "Mac-2BD1B31983FE1663",
  make_array(
    "efi-version", "MBP112.88Z.0138.B16.1509081314"
  ),
  "Mac-AFD8A9D944EA4843",
  make_array(
    "efi-version", "MBP102.88Z.0106.B0A.1509130955"
  )
);

# Modeled after check actual patch performs
# if the SMC gets "borked" it reports as "0.000"
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoSMCVersions(actual, intended)
{
  local_var pat, item_actual, item_intended,
            actualMajorVersion, actualMinorVersion,
            actualBuildType, actualBuildNumber,
            intendedMajorVersion, intendedMinorVersion,
            intendedBuildType, intendedBuildNumber;

  # borked version checks
  if(actual == "0.000" && intended == "0.000") return 0;
  if(actual == "0.000" && intended != "0.000") return -1;
  if(actual != "0.000" && intended == "0.000") return 1;

  pat = "^(\d+)\.(\d+)([a-f]{1})(\d+)$";
  item_actual = eregmatch(pattern: pat, string: actual);
  item_intended = eregmatch(pattern: pat, string: intended);

  if(isnull(item_actual) || isnull(item_intended)) return -2;

  actualMajorVersion = int(item_actual[1]);
  actualMinorVersion = int(item_actual[2]);
  actualBuildType = item_actual[3];
  actualBuildNumber = int(item_actual[4]);

  intendedMajorVersion = int(item_intended[1]);
  intendedMinorVersion = int(item_intended[2]);
  intendedBuildType = item_intended[3];
  intendedBuildNumber = int(item_intended[4]);

  if(actualMajorVersion != intendedMajorVersion) return -2;
  if(actualMinorVersion != intendedMinorVersion) return -2;

  if(actualBuildType !~ "^[abf]$" || intendedBuildType !~ "^[abf]$")
    return -2;

  if(actualBuildType < intendedBuildType) return -1;
  if(actualBuildType > intendedBuildType) return 1;

  if(actualBuildNumber < intendedBuildNumber) return -1;
  if(actualBuildNumber > intendedBuildNumber) return 1;

  return 0;
}

# Modeled after check patch performs
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoEFIVersions(actual, intended)
{
  local_var actual_array, intended_array,
            actual_minor_version, intended_minor_version,
            actual_major_version, intended_major_version;

  actual_array = split(actual, sep:'.', keep:FALSE);
  intended_array = split(intended, sep:'.', keep:FALSE);

  if(max_index(actual_array) != 5 || max_index(intended_array) != 5)
    return -2;

  if(actual_array[0] != intended_array[0]) return -2;
  if(actual_array[1] != "88Z" || intended_array[1] != "88Z") return -2;

  if(actual_array[2] !~ "^[\da-fA-F]{4}$" ||
     intended_array[2] !~ "^[\da-fA-F]{4}$") return -2;

  # don't know why, but this check is in the patch
  if(actual_array[3][0] =~ "[dD]" || intended_array[3][0] =~ "[dD]")
    return -2;

  actual_minor_version = substr(actual_array[3], 1);
  intended_minor_version = substr(intended_array[3], 1);

  if(actual_minor_version !~ "^[\da-fA-F]{2}$" ||
     intended_minor_version !~ "^[\da-fA-F]{2}$") return -2;

  actual_minor_version = ord(hex2raw(s:actual_minor_version));
  intended_minor_version = ord(hex2raw(s:intended_minor_version));

  actual_major_version = getword(blob:hex2raw(s:actual_array[2]),
                                 pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  intended_major_version = getword(blob:hex2raw(s:intended_array[2]),
                                   pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  
  if(actual_major_version > intended_major_version) return 1;
  if(actual_major_version < intended_major_version) return -1;
  if(actual_minor_version > intended_minor_version) return 1;
  if(actual_minor_version < intended_minor_version) return -1;

  return 0;
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Available for: OS X Mavericks v10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.9\.5([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.9.5");

board_id_cmd = 'ioreg -l | awk -F \\" \'/board-id/ { print $4 }\'';
efi_version_cmd = 'ioreg -p IODeviceTree -n rom@0 | awk -F \\" \'/version/ { print $4 }\'';
smc_version_cmd = 'ioreg -l | awk -F \\" \'/smc-version/ { print $4 }\'';

results = exec_cmds(cmds:make_list(board_id_cmd, efi_version_cmd, smc_version_cmd));

# these may not be considered an 'error' if host is a VM running on non Apple hardware
if(isnull(results)) exit(0, "Unable to obtain hardware information on remote host.");

if(isnull(results[board_id_cmd]) || results[board_id_cmd] !~ "^Mac-[a-fA-F\d]+$")
  exit(0, 'No valid Mac board ID found.');

if(isnull(results[efi_version_cmd]) || ".88Z." >!< results[efi_version_cmd])
  exit(0, 'No valid Mac EFI version found.');

if(isnull(results[smc_version_cmd]) || results[smc_version_cmd] !~ "^(\d+)\.([\da-f]+)$")
  exit(0, 'No valid Mac SMC version found.');

board_id = results[board_id_cmd];
efi_version = results[efi_version_cmd];
smc_version = results[smc_version_cmd];

if(isnull(efi_fixes[board_id])) exit(0, "The remote host does not have an affected board ID (" + board_id + ").");

efi_fix = efi_fixes[board_id]["efi-version"];
min_smc_ver = efi_fixes[board_id]["minimum-smc-version"];

if(!isnull(min_smc_ver))
{
  if(compareTwoSMCVersions(actual:smc_version, intended:min_smc_ver) < 0)
    exit(0, "SMC version " + smc_version + " is too old to allow update.");
}

res = compareTwoEFIVersions(actual:efi_version, intended:efi_fix);
if(res == -2)
  exit(1, "Error comparing EFI version (" + efi_version + ") to fixed version (" + efi_fix + ").");

if(res >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "Apple EFI", efi_version);

port = 0;

if(report_verbosity > 0)
{
  report = '\n  Board ID              : ' + board_id +
           '\n  Installed EFI version : ' + efi_version +
           '\n  Fixed EFI version     : ' + efi_fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
