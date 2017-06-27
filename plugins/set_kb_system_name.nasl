#TRUSTED 6d541ce30bc5cb64b24b5dcfc6321dd6bf5cd4abdb44606772ae09e1807bbfd7981678148add6ec5ab3c90a914cc7d01ec5a2403a90e3a26e0c8fce4e0afcc8aab0a9f4c75e257d088de1d1ce198340ae900a05a846af4ad8107961a85c7fffae6c82367b6dbc8bc65451291edd213e73dd74f8bbf05e46515fca7f0860540089dbf2191f8238889c693dccd267f592242e3d681133b26794b926ba74b60cdac720bc724c2308b539f2ba46f316e782c8725f7ee6ea309597270f957abf2a28e349e6f0dd9db28f2c39faa275285b5eecfd3d8a7bbb61fc1399c2450a213acc59d2c705e51b7752994badf5fa3c0ae975b14e384323decf9ead834d97a7aee912207ed7b944f785de50a6dd6e5bf0b11c20c9e7eef4708d08620ba3a5f09f2bcd373a7ede6b149998ff1d9563ab8dd7be1dd02dc2a394ad2df6a92e8fc0388568af176e44879bab436a6d62bccae96a00c7772e9a2801b4e14a0e9b44f445c711ead2668ce21d6dad571cd213ce832fdafd2ca16075a662f770f0e243ec5a2d4cae01d99f7a64d50ff6854f5f77f12496a5ff3775058920c97d3b3d17ca4bd6792a793f7d3f7dca7238f5935e2afd94437eea980dc806d24042b64eb28d60ce36ac5edc9157631a8749aba6b94cb15fb336e03f04bddcabf126f4c340e22262532e7dd35cb0b54f1f0b1665037c38eb10e2037cac7b96a12860db8f56069bc0e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92440);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/19");

  script_name(english:"Set System Name");
  script_summary(english:"Get the name set in the UI for the system and set it locally for use.");  

  script_set_attribute(attribute:"synopsis", value:
"Used by other plugins to get system name.");
  script_set_attribute(attribute:"description", value:
"Get the system name that was input into the UI and set it locally for
use in other plugins.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

name = set_system_name();

if (isnull(name))
{
  exit(0, "Failed to set system name.");
}
