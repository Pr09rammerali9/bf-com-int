#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <stack>
#include <unistd.h>
#include <sys/syscall.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Constants.h>
#include <llvm/Support/raw_ostream.h>

#define CMD_DEREF '@'
#define CMD_EXTERN_CALL '^'
#define CMD_GET_INDEX '$'
#define CMD_FUNC_START '{'
#define CMD_FUNC_END '}'
#define CMD_RETURN '_'
#define CMD_SYSCALL '!'
#define CMD_PREPROC_INC "%inc"
#define CMD_PREPROC_GRD "%grd"

static llvm::LLVMContext TheContext;
static llvm::IRBuilder<> Builder(TheContext);
static std::unique_ptr<llvm::Module> TheModule;
static llvm::GlobalVariable* Tape;
static llvm::GlobalVariable* DataPointer;
static std::map<std::string, std::string> FunctionCode;

void create_deref_op() {
    llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
    llvm::Value* addr_ptr = Builder.CreatePointerCast(current_dp, Builder.getInt64PtrTy());
    llvm::Value* raw_addr = Builder.CreateLoad(Builder.getInt64Ty(), addr_ptr);
    
    llvm::Value* real_ptr = Builder.CreateIntToPtr(raw_addr, Builder.getInt8PtrTy());
    llvm::Value* fetched_val = Builder.CreateLoad(Builder.getInt8Ty(), real_ptr);
    
    Builder.CreateStore(fetched_val, current_dp);
}

void create_index_op() {
    llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
    llvm::Value* tape_start = Builder.CreateInBoundsGEP(Tape->getValueType(), Tape, 
                              {Builder.getInt64(0), Builder.getInt64(0)});
    
    llvm::Value* diff = Builder.CreatePtrDiff(Builder.getInt8Ty(), current_dp, tape_start);
    Builder.CreateStore(Builder.CreateTrunc(diff, Builder.getInt8Ty()), current_dp);
}

void compile_block(const std::string& block_code, const std::string& func_name = "") {
    llvm::Function* F = Builder.GetInsertBlock()->getParent();
    size_t ip = 0;

    while(ip < block_code.length()){
        switch(block_code[ip]){
            case '>': {
                llvm::Value* ptr = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                Builder.CreateStore(Builder.CreateGEP(Builder.getInt8Ty(), ptr, Builder.getInt64(1)), DataPointer);
            } break;
            case '+': {
                llvm::Value* ptr = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* val = Builder.CreateLoad(Builder.getInt8Ty(), ptr);
                Builder.CreateStore(Builder.CreateAdd(val, Builder.getInt8(1)), ptr);
            } break;
            case CMD_DEREF: 
                create_deref_op(); 
                break;
            case CMD_GET_INDEX: 
                create_index_op(); 
                break;
            case CMD_EXTERN_CALL: {
                llvm::Function* ext_f = TheModule->getFunction("sm_auc_u40");
                if (ext_f) Builder.CreateCall(ext_f);
            } break;
            case CMD_SYSCALL: {
                llvm::Function* sys_f = TheModule->getFunction("syscall");
            } break;
        }
        ip++;
    }
}
