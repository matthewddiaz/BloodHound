$folderMax = 5;

for($fileNum = 1; $fileNum -lt 22; $fileNum++){
    $correspondingFolder =  [math]::ceiling($fileNum / $folderMax);
    Move-Item .\BloodHound$fileNum.ps1 .\BloodHoundPart$correspondingFolder\BloodHound$fileNum.ps1;
}