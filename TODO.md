AutoRuns PowerShell Module `TODO` list
======================================

### Coding best practices
- [x] Use PSScriptAnalyzer module to validate the code follows best practices
- [ ] Write Pester tests for this module

### OS and Software compatibility
- [ ] Test the module on Nano and get rid of Add-Member cmdlet
- [ ] Test the module on 1607 versions of Windows 10
- [ ] Test the module on Windows RT
- [ ] Review Office Add-ins code with Office x86 and x64 versions

### General improvements
- [ ] Write a better implementation of the internal Get-RegValue function
- [ ] Review and improve regex used by the internal Get-PSPrettyAutorun function (ex: external paths)

### New features
- [ ] Replace HKCU and add an option to specify what user hive is being investigated
- [ ] Add timestamps on registry keys
- [ ] Analyze an offline image of Windows

### Help
- [ ] More examples
- [ ] Use external help? 
- [ ] Internationalization?
- [ ] Copy the commetented changelog at the end of the module in README.md
- [ ] Document issues and write a pester tests to validate the module behavior if fixed