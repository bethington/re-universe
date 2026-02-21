# Missing D2Server.dll for Diablo 2 v1.00

## Overview
D2Server.dll is a critical server-side binary that was accidentally included in the original Diablo 2 v1.00 release but removed in subsequent versions. This file is essential for a complete analysis of the original D2 architecture.

## Historical Significance
- **Accidental inclusion**: Blizzard accidentally packaged D2Server.dll with D2 v1.00
- **Server functionality**: Runs realm server and supporting services with D2Game.dll
- **Private servers**: Foundation for D2GS (Diablo II Game Server) development
- **Unique insights**: Only server-side binary ever publicly available

## Technical Details
- **Version**: v0.1.0.0 (based on community reports)
- **Purpose**: Hosts multiple games for clients to connect to
- **Integration**: Works with D2Game.dll and Game.exe (-server command line switch)
- **Network**: Handles client-server communication protocols

## Known Sources
1. **Original 1.00 Setup MPQ**: `SetupDat\Files103\D2Server.dll`
2. **The Phrozen Keep**: Community archive (link currently broken)
3. **D2GS Projects**: May contain original or modified versions
4. **Original Retail Discs**: Very early 1.00 releases (most are actually 1.03)

## Acquisition Plan
- [ ] Check community forums (The Phrozen Keep, D2GS communities)
- [ ] Search for original 1.00 retail disc images
- [ ] Contact D2 preservation communities
- [ ] Verify authenticity with MD5/SHA256 hashes when found

## Research Value
Once acquired, D2Server.dll will provide:
- Server-side game logic analysis
- Network protocol reverse engineering
- Anti-cheat mechanism insights
- Historical Blizzard server architecture study
- Comparison with client-side implementations

## File Status
**STATUS**: ✅ ACQUIRED - Successfully added to repository!
**PRIORITY**: HIGH - Unique research opportunity
**SIZE**: 84,480 bytes (84KB)
**MD5 HASH**: 4c63719b7dd13f1f0535a78a376895dc

---
Generated during binaries reorganization - February 2026