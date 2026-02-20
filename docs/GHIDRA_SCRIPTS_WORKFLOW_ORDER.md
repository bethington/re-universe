# BSim Analysis Workflow - Script Execution Order

## 📋 **Core Workflow (Required Steps)**

### **Step 1: Binary Ingestion** ✅ **REQUIRED FIRST STEP**
**Script**: `Step1_AddProgramToBSimDatabase.java`
- **Purpose**: Primary ingestion script - mandatory first step for all BSim analysis
- **Menu**: `Tools.BSim.Step1 - Add Program to Database`
- **Features**: Unified version system support, automatic version detection, validation
- **Input**: Ghidra programs (single, project-wide, or version-filtered)
- **Output**: Executable records with unified version metadata, function data
- **Dependencies**: None (starting point)

### **Step 2: Signature Generation** ✅ **REQUIRED SECOND STEP**
**Script**: `Step2_GenerateBSimSignatures.java`
- **Purpose**: Creates mathematical signatures enabling cross-version similarity analysis
- **Menu**: `Tools.BSim.Step2 - Generate Enhanced Signatures`
- **Features**: LSH signatures, control flow analysis, version-aware optimization
- **Input**: Functions from Step1, processes all or filtered by version
- **Output**: Enhanced function signatures optimized for unified system
- **Dependencies**: Requires Step1 completion

---

## 📊 **Optional Enrichment Steps (Step 3)**

### **Step 3: Comments** 🔧 **OPTIONAL**
**Script**: `Step3_PopulateCommentsIntoBSim.java`
- **Purpose**: Sync analyst-created comments to BSim database
- **Menu**: `Tools.BSim.Step3 - Populate Comments (Optional)`
- **Note**: String references, cross-references, signatures, and import/exports are now automatically populated during Step1

---

## 🎯 **Analysis Steps (Required for Results)**

### **Step 4: Similarity Matrix** ✅ **REQUIRED**
**Script**: `Step4_GenerateFunctionSimilarityMatrix.java`
- **Purpose**: Generate cross-version function similarity matrix
- **Menu**: `Tools.BSim.Step4 - Generate Similarity Matrix`
- **Input**: Signatures and optional enrichment data
- **Output**: Function similarity analysis results

### **Step 5: Complete Workflow** 🚀 **AUTOMATED**
**Script**: `Step5_CompleteSimilarityWorkflow.java`
- **Purpose**: Complete automated similarity analysis pipeline
- **Menu**: `Tools.BSim.Step5 - Complete Similarity Workflow`
- **Input**: All previous steps
- **Output**: Comprehensive similarity analysis

---

## 📈 **Execution Workflows**

### **🚀 Quick Start (Minimal)**
1. **Step 1**: Add programs to database
2. **Step 2**: Generate signatures
3. **Step 4**: Generate similarity matrix

### **📊 Standard Workflow (Recommended)**
1. **Step 1**: Add programs to database
2. **Step 2**: Generate signatures
3. **Step 3a**: Populate comments *(optional)*
4. **Step 3b**: Populate string references *(optional)*
5. **Step 4**: Generate similarity matrix

### **🔬 Complete Analysis (Full Featured)**
1. **Step 1**: Add programs to database (includes strings, cross-refs, signatures, imports/exports)
2. **Step 2**: Generate signatures
3. **Step 3**: Populate comments *(optional - for syncing analyst comments)*
4. **Step 4**: Generate similarity matrix
5. **Step 5**: Complete automated workflow

### **⚡ Automated (Single Command)**
- **Step 5**: Complete workflow (runs all necessary steps)

---

## 🎯 **Step Dependencies**

```
Step 1 (Required) → Step 2 (Required) → Step 3 (Optional) → Step 4 (Required)
                                                           ↓
                                          Step 5 (Automated - Runs All)
```

---

## 📋 **Menu Organization**

In Ghidra, the scripts appear in this logical order:
```
Tools.BSim.
├── Step1 - Add Program to Database
├── Step2 - Generate Enhanced Signatures
├── Step3 - Populate Comments (Optional)
├── Step4 - Generate Similarity Matrix
└── Step5 - Complete Similarity Workflow
```

---

## ✅ **Database Configuration**

All scripts are configured for remote database connectivity:
- **Database**: `postgresql://10.0.0.30:5432/bsim`
- **User**: `ben`
- **Schema**: Unified version system compatible

---

## 🎯 **File Naming Convention Support**

Scripts support unified naming conventions:
- **Standard**: `1.03_D2Game.dll` → version: 1.03, family: Unified
- **Exception**: `Classic_1.03_Game.exe` → version: 1.03, family: Classic

The numbered workflow makes it clear which scripts to run and in what order for successful BSim analysis.