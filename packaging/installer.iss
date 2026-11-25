; ADmiral installer (Inno Setup 6).
;
; Build after the self-contained folder build (see packaging\build.ps1):
;   dotnet publish src\ADmiral.Desktop -c Release -r win-x64 --self-contained -o dist\ADmiral
;   ISCC packaging\installer.iss /DAppVersion=0.6.2 [/DSourceDir=<publish folder>]
;
; The installer always installs for all users (administrator rights, one UAC prompt):
;   * program folder: Program Files\ADmiral (can be changed on the folder page),
;   * data (settings, database, log): C:\ProgramData\ADmiral, restricted to SYSTEM, Administrators and the
;     installing user (plus /DATAUSER=, e.g. a group "CORP\ADmiral-Admins"); never writable by every user,
;   * Start menu / desktop shortcuts.
; Starts with the license information (license-hu.txt / license-en.txt, by the installer language): ADmiral is GPL-3.0,
; so it is an information page (no "I accept"); the full license text is installed as {app}\LICENSE.txt.
; Unattended:
;   ADmiral-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /DIR="D:\Apps\ADmiral" [/DATADIR="D:\ADmiral-adatok"]
;                     [/DATAUSER="CORP\ADmiral-Admins"] [/CURRENTUSER="CORP\jdoe" | /CURRENTUSER=none]
;   /DATAUSER=     one more account or group (name or *SID) that may change the data folder
;   /CURRENTUSER=  the account that counts as "the installing user" (name or *SID). Default: the user running setup.
;                  Useful when setup runs as SYSTEM (software distribution) or UAC was answered by another
;                  administrator; "none" grants nothing beyond SYSTEM, Administrators and /DATAUSER=.
; The in-program updater passes /DATAUSER=*<SID of the user running ADmiral> (and no /DATADIR=: an upgrade keeps the
; data folder recorded in {app}\admiral-data.txt).
; Every run writes the data folder's DACL from scratch (nothing of an earlier or pre-planted ACL survives) and records
; the accounts it granted in {app}\admiral-datausers.txt; ADmiral refuses / re-restricts a data folder that any other
; account can change.

#define AppName "ADmiral"
#ifndef AppVersion
  #define AppVersion "0.6.2"
#endif
; The version shown and used in the file name; a beta build passes e.g. /DVersionLabel=0.6.2-beta.7 with a numeric
; /DAppVersion=0.6.2.7 (Windows' file version must be numbers only). Normal builds: the same as AppVersion.
#ifndef VersionLabel
  #define VersionLabel AppVersion
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\ADmiral"
#endif
#define ServiceName "ADmiralRetry"

[Setup]
AppId={{C6865C1C-D795-424A-AA11-A858F9475B4D}
AppName={#AppName}
AppVersion={#VersionLabel}
AppVerName={#AppName} {#VersionLabel}
AppPublisher=TidecrestLabs
AppPublisherURL=https://tidecrestlabs.com/
AppSupportURL=https://tidecrestlabs.com/
AppComments=Read-only Active Directory inventory and deployment targeting
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=no
UsePreviousAppDir=yes
; Always for all users: no per-user / all-users choice.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=ADmiral-Setup-{#VersionLabel}
SetupIconFile=..\src\ADmiral.Web\wwwroot\admiral.ico
UninstallDisplayIcon={app}\ADmiral.exe
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
InfoBeforeFile=license-en.txt
CloseApplications=yes
ShowLanguageDialog=auto
LanguageDetectionMethod=uilanguage

[Languages]
Name: "hu"; MessagesFile: "compiler:Languages\Hungarian.isl"; InfoBeforeFile: "license-hu.txt"
Name: "en"; MessagesFile: "compiler:Default.isl"; InfoBeforeFile: "license-en.txt"

[CustomMessages]
hu.LaunchApp=ADmiral indítása
hu.WebView2Missing=Az ADmiral ablakához a Microsoft Edge WebView2 Runtime szükséges, ami nem található ezen a gépen.%n%nTelepítse a Microsofttól („Evergreen WebView2 Runtime”), majd indítsa el az ADmiralt.
hu.WebView2Installing=Microsoft Edge WebView2 Runtime telepítése...
hu.RemoveData=Törli az ADmiral adatait is (beállítások, adatbázis, napló)?%n%n%1%n%nA „Nem” megtartja őket egy későbbi újratelepítéshez.
en.LaunchApp=Launch ADmiral
en.WebView2Missing=ADmiral's window needs the Microsoft Edge WebView2 Runtime, which was not found on this computer.%n%nInstall it from Microsoft ("Evergreen WebView2 Runtime"), then start ADmiral.
en.WebView2Installing=Installing Microsoft Edge WebView2 Runtime...
en.RemoveData=Also delete ADmiral's data (settings, database, log)?%n%n%1%n%nChoose "No" to keep it for a later reinstall.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; copies of the login-tracking script of 0.5.1 (now runs without a file on disk)
Type: files; Name: "{commonappdata}\ADmiral\ADmiral-Logins.ps1"
; the Python (PyInstaller) build of 0.5.x installed into the same folder
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\ADmiral.exe.config"

[Dirs]
; a custom /DIR= outside Program Files gets the same protection (see SecureAppDir: a fresh, protected DACL)
Name: "{app}"; Permissions: admins-full system-full users-readexec

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
#ifexist "MicrosoftEdgeWebview2Setup.exe"
Source: "MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NeedsWebView2
#endif

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\ADmiral.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\ADmiral.exe"; Tasks: desktopicon

[Run]
#ifexist "MicrosoftEdgeWebview2Setup.exe"
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "{cm:WebView2Installing}"; Check: NeedsWebView2; Flags: waituntilterminated
#endif
Filename: "{app}\ADmiral.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; the "ADmiral retry" service points at {app}\ADmiral.exe: remove it with the program
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"

[UninstallDelete]
Type: files; Name: "{app}\admiral-data.txt"
Type: files; Name: "{app}\admiral-datausers.txt"

[Code]
const
  WebView2Key = 'Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

var
  ServiceWasRunning: Boolean;

function HasVersion(Root: Integer; Key: String): Boolean;
var
  V: String;
begin
  Result := RegQueryStringValue(Root, Key, 'pv', V) and (V <> '') and (V <> '0.0.0.0');
end;

function WebView2Installed: Boolean;
begin
  Result := HasVersion(HKLM, 'SOFTWARE\WOW6432Node\' + WebView2Key)
         or HasVersion(HKLM, 'SOFTWARE\' + WebView2Key)
         or HasVersion(HKCU, 'Software\' + WebView2Key);
end;

function NeedsWebView2: Boolean;
begin
  Result := not WebView2Installed;
end;

function DefaultDataDir: String;
begin
  Result := ExpandConstant('{commonappdata}\ADmiral');
end;

function PointerFile: String;
begin
  Result := ExpandConstant('{app}\admiral-data.txt');
end;

function DataUsersFile: String;
begin
  Result := ExpandConstant('{app}\admiral-datausers.txt');
end;

// The data folder an earlier installation recorded (empty when there is none).
function ExistingDataDir: String;
var
  Lines: TArrayOfString;
begin
  Result := '';
  if LoadStringsFromFile(PointerFile, Lines) and (GetArrayLength(Lines) > 0) then
    Result := Trim(Lines[0]);
end;

// /DATADIR= when given; else the folder of an earlier installation (upgrades, the in-program updater); else
// C:\ProgramData\ADmiral.
function DataDir(Param: String): String;
begin
  Result := ExpandConstant('{param:DATADIR|}');
  if Result = '' then Result := ExistingDataDir;
  if Result = '' then Result := DefaultDataDir;
end;

// An account name for icacls: quotes and control characters removed (it is passed inside one quoted argument).
function CleanAccount(S: String): String;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
    if (S[I] <> '"') and (Ord(S[I]) >= 32) then
      Result := Result + S[I];
  Result := Trim(Result);
end;

// The "installing user": /CURRENTUSER= when given ("none" = nobody), else the user running setup.
function InstallingUser: String;
begin
  Result := CleanAccount(ExpandConstant('{param:CURRENTUSER|}'));
  if CompareText(Result, 'none') = 0 then
  begin
    Result := '';
    Exit;
  end;
  if Result = '' then
  begin
    Result := GetEnv('USERDOMAIN');
    if Result <> '' then Result := Result + '\';
    Result := Result + GetUserNameString;
  end;
end;

procedure Icacls(Params: String);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\icacls.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Take ownership with SeTakeOwnershipPrivilege (works even when a pre-planted DACL locks Administrators out).
procedure TakeOwn(Dir: String);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\takeown.exe'), '/F "' + Dir + '" /A', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure AddAccount(var List: TArrayOfString; Account: String);
var
  I, N: Integer;
begin
  Account := CleanAccount(Account);
  if (Account = '') or (CompareText(Account, 'LocalSystem') = 0) or (CompareText(Account, 'NT AUTHORITY\SYSTEM') = 0) then Exit;
  if Copy(Account, 1, 2) = '.\' then Account := GetComputerNameString + Copy(Account, 2, Length(Account));
  N := GetArrayLength(List);
  for I := 0 to N - 1 do
    if CompareText(List[I], Account) = 0 then Exit;
  SetArrayLength(List, N + 1);
  List[N] := Account;
end;

// The accounts that get modify rights on the data folder: the installing user, /DATAUSER=, the accounts an earlier
// run recorded (an upgrade keeps them) and the account of an installed retry service.
function DataUsers: TArrayOfString;
var
  Lines: TArrayOfString;
  I: Integer;
  Svc: String;
begin
  SetArrayLength(Result, 0);
  AddAccount(Result, InstallingUser);
  AddAccount(Result, ExpandConstant('{param:DATAUSER|}'));
  if LoadStringsFromFile(DataUsersFile, Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
      if (Trim(Lines[I]) <> '') and (Copy(Trim(Lines[I]), 1, 1) <> '#') then
        AddAccount(Result, Lines[I]);
  if RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}', 'ObjectName', Svc) then
    AddAccount(Result, Svc);
end;

// The data folder holds the settings, the package library and the database the administrator acts on: only SYSTEM,
// Administrators and the ADmiral users may change it. The DACL is written from scratch: ownership is taken first
// (Administrators), /reset drops every explicit entry - including one a user who created the folder before the
// installation gave themselves - and /inheritance:r /grant:r then leaves exactly the intended entries. OWNER RIGHTS is
// limited to read, so files someone else created there earlier cannot be re-opened by them. Children: owner
// Administrators, explicit entries dropped (they inherit the folder's). ADmiral itself re-checks at every start.
procedure SecureDataDir;
var
  Dir, Grants: String;
  Users: TArrayOfString;
  I: Integer;
begin
  Dir := DataDir('');
  Users := DataUsers;
  Grants := '*S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-3-4:(OI)(CI)RX';
  for I := 0 to GetArrayLength(Users) - 1 do
    Grants := Grants + ' "' + Users[I] + ':(OI)(CI)M"';
  TakeOwn(Dir);
  Icacls('"' + Dir + '" /setowner *S-1-5-32-544 /C /Q');
  Icacls('"' + Dir + '" /reset /C /Q');
  Icacls('"' + Dir + '" /inheritance:r /grant:r ' + Grants);
  Icacls('"' + Dir + '" /remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 *S-1-5-4');
  Icacls('"' + Dir + '\*" /setowner *S-1-5-32-544 /T /C /Q');
  Icacls('"' + Dir + '\*" /reset /T /C /Q');
  SaveStringsToUTF8File(DataUsersFile, Users, False);
end;

// A program folder outside Program Files (custom /DIR=) inherits whatever its parent allows (e.g. D:\ lets every user
// create files): give it a fresh, protected DACL - SYSTEM / Administrators full control, Users read & execute - before
// the program files are copied, so no user can add or replace a DLL next to ADmiral.exe.
procedure SecureAppDir;
var
  Dir, Pf: String;
begin
  Dir := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
  Pf := RemoveBackslashUnlessRoot(ExpandConstant('{commonpf64}'));
  if CompareText(Copy(Dir, 1, Length(Pf) + 1), Pf + '\') = 0 then Exit;   // Program Files is already protected
  ForceDirectories(Dir);
  TakeOwn(Dir);
  Icacls('"' + Dir + '" /setowner *S-1-5-32-544 /C /Q');
  Icacls('"' + Dir + '" /reset /C /Q');
  Icacls('"' + Dir + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX');
  Icacls('"' + Dir + '\*" /setowner *S-1-5-32-544 /T /C /Q');
  Icacls('"' + Dir + '\*" /reset /T /C /Q');
end;

// The retry service runs ADmiral.exe from {app}: stop it before the files are replaced, start it again afterwards.
// (sc.exe exits 0 when a stop was sent, 1062 when it was not running, 1060 when it is not installed.)
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  ServiceWasRunning := Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
                       and (ResultCode = 0);
  // the service finishes a running pass within 25 s; CloseApplications (Restart Manager) covers the rest
  if ServiceWasRunning then
    Sleep(5000);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
    SecureAppDir;
  if CurStep = ssPostInstall then
  begin
    ForceDirectories(DataDir(''));
    SecureDataDir;
    // only a new choice is recorded: an upgrade without /DATADIR= keeps the folder it already uses
    if (ExpandConstant('{param:DATADIR|}') <> '') or (ExistingDataDir = '') then
      SaveStringsToUTF8File(PointerFile, [DataDir('')], False);
    if ServiceWasRunning then
      Exec(ExpandConstant('{sys}\sc.exe'), 'start {#ServiceName}', '', SW_HIDE, ewNoWait, ResultCode);
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and NeedsWebView2 then
    MsgBox(CustomMessage('WebView2Missing'), mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Lines: TArrayOfString;
  Dir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    Dir := DefaultDataDir;
    if LoadStringsFromFile(ExpandConstant('{app}\admiral-data.txt'), Lines) and (GetArrayLength(Lines) > 0) and (Trim(Lines[0]) <> '') then
      Dir := Trim(Lines[0]);
    // Only ever asked interactively, and "No" is the default: silent uninstalls keep the data.
    if (not UninstallSilent) and DirExists(Dir) then
      if MsgBox(FmtMessage(CustomMessage('RemoveData'), [Dir]), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Dir, True, True, True);
  end;
end;
