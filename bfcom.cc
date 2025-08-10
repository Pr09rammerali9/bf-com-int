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

#define CUSTOM_CMD_FUNC_START '{'
#define CUSTOM_CMD_FUNC_END '}'
#define CUSTOM_CMD_FUNC_CALL '@'
#define CUSTOM_CMD_RETURN '_'
#define CUSTOM_CMD_FILE_OPEN '$'
#define CUSTOM_CMD_FILE_CLOSE '~'
#define CUSTOM_CMD_FILE_WRITE '#'
#define CUSTOM_CMD_FILE_READ '^'
#define CUSTOM_CMD_SYSCALL '!'
#define CUSTOM_CMD_PREPROC_INC "%inc"
#define CUSTOM_CMD_PREPROC_GRD "%grd"
#define CUSTOM_CMD_COND_START '"'
#define CUSTOM_CMD_COND_BLOCK '`'

static llvm::LLVMContext TheContext;
static llvm::IRBuilder<> Builder(TheContext);
static std::unique_ptr<llvm::Module> TheModule;
static std::map<std::string, llvm::Function*> FunctionTable;

static llvm::GlobalVariable* Tape;
static llvm::GlobalVariable* DataPointer;
static llvm::GlobalVariable* FileHandle;
static std::map<std::string, std::string> FunctionCode;

std::string read_file_to_string(const std::string& filename) {
    std::ifstream t(filename);
    std::string str((std::istreambuf_iterator<char>(t)),
                    std::istreambuf_iterator<char>());
    return str;
}

std::string preprocess_code(const std::string& code_in) {
    std::string code_out = code_in;
    size_t ip = 0;
    std::vector<std::string> included_files;

    while (ip < code_out.length()) {
        if (code_out[ip] == '%') {
            size_t directive_len = 0;
            bool is_guarded = false;

            if (code_out.substr(ip, 4) == CUSTOM_CMD_PREPROC_INC) {
                directive_len = 4;
            } else if (code_out.substr(ip, 4) == CUSTOM_CMD_PREPROC_GRD) {
                directive_len = 4;
                is_guarded = true;
            }

            if (directive_len > 0) {
                size_t filename_start = ip + directive_len + 1;
                size_t filename_end = code_out.find('\n', filename_start);
                if (filename_end == std::string::npos) {
                    filename_end = code_out.length();
                }

                std::string filename = code_out.substr(filename_start, filename_end - filename_start);

                bool already_included = false;
                for(const auto& inc_file : included_files) {
                    if(inc_file == filename) {
                        already_included = true;
                        break;
                    }
                }

                if (is_guarded && already_included) {
                    code_out.erase(ip, filename_end - ip + 1);
                    continue;
                }

                if (is_guarded) {
                    included_files.push_back(filename);
                }

                std::string included_code = read_file_to_string(filename);
                code_out.replace(ip, filename_end - ip + 1, included_code);
                continue;
            }
        }
        ip++;
    }

    return code_out;
}

size_t find_matching_bracket(const std::string& code, size_t ip) {
    size_t open_brackets = 1;
    while (ip < code.length()) {
        ip++;
        if (code[ip] == '[') {
            open_brackets++;
        } else if (code[ip] == ']') {
            open_brackets--;
            if (open_brackets == 0) {
                return ip;
            }
        }
    }
    throw std::runtime_error("Mismatched brackets");
}

size_t find_matching_cond_end(const std::string& code, size_t ip) {
    size_t open_conds = 1;
    while (ip < code.length()) {
        ip++;
        if (code.substr(ip, 5) == "\"cond") {
            open_conds++;
        } else if (code[ip] == '`') {
            open_conds--;
            if (open_conds == 0) {
                return ip;
            }
        }
    }
    throw std::runtime_error("Mismatched conditional blocks");
}

void register_functions(const std::string& code) {
    size_t ip = 0;
    while (ip < code.length()) {
        if (code[ip] == CUSTOM_CMD_FUNC_START) {
            size_t func_name_start = ip + 1;
            size_t func_name_end = code.find('\n', func_name_start);
            if (func_name_end == std::string::npos) {
                throw std::runtime_error("Function name not found");
            }
            std::string func_name = code.substr(func_name_start, func_name_end - func_name_start);

            size_t brace_counter = 1;
            size_t body_start = func_name_end + 1;
            size_t body_end = body_start;
            while (brace_counter > 0 && body_end < code.length()) {
                if (code[body_end] == CUSTOM_CMD_FUNC_START) brace_counter++;
                if (code[body_end] == CUSTOM_CMD_FUNC_END) brace_counter--;
                body_end++;
            }
            if (brace_counter != 0) {
                throw std::runtime_error("Mismatched function braces");
            }

            FunctionCode[func_name] = code.substr(body_start, body_end - body_start - 1);
            ip = body_end;
        }
        ip++;
    }
}

void compile_block(const std::string& block_code, const std::string& func_name = "") {
    llvm::Function* F = nullptr;
    if (func_name.empty()) {
        F = Builder.GetInsertBlock()->getParent();
    } else {
        F = llvm::Function::Create(llvm::FunctionType::get(Builder.getVoidTy(), false), llvm::Function::ExternalLinkage, func_name, TheModule.get());
        llvm::BasicBlock* BB = llvm::BasicBlock::Create(TheContext, "entry", F);
        Builder.SetInsertPoint(BB);
    }
    
    size_t ip = 0;
    while(ip < block_code.length()){
        switch(block_code[ip]){
            case '>':
            {
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* new_dp = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(1));
                Builder.CreateStore(new_dp, DataPointer);
            }
            break;
            case '<':
            {
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* new_dp = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(-1));
                Builder.CreateStore(new_dp, DataPointer);
            }
            break;
            case '+':
            {
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                llvm::Value* inc_val = Builder.CreateAdd(loaded_val, Builder.getInt8(1));
                Builder.CreateStore(inc_val, current_dp);
            }
            break;
            case '-':
            {
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                llvm::Value* dec_val = Builder.CreateSub(loaded_val, Builder.getInt8(1));
                Builder.CreateStore(dec_val, current_dp);
            }
            break;
            case '.':
            {
                llvm::Function* putchar_func = TheModule->getFunction("putchar");
                if (!putchar_func) {
                    llvm::FunctionType* putchar_ft = llvm::FunctionType::get(Builder.getInt32Ty(), {Builder.getInt32Ty()}, false);
                    putchar_func = llvm::Function::Create(putchar_ft, llvm::Function::ExternalLinkage, "putchar", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                Builder.CreateCall(putchar_func, {Builder.CreateZExt(loaded_val, Builder.getInt32Ty())});
            }
            break;
            case ',':
            {
                llvm::Function* getchar_func = TheModule->getFunction("getchar");
                if (!getchar_func) {
                    llvm::FunctionType* getchar_ft = llvm::FunctionType::get(Builder.getInt32Ty(), {}, false);
                    getchar_func = llvm::Function::Create(getchar_ft, llvm::Function::ExternalLinkage, "getchar", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* input_char = Builder.CreateCall(getchar_func);
                Builder.CreateStore(Builder.CreateTrunc(input_char, Builder.getInt8Ty()), current_dp);
            }
            break;
            case '[':
            {
                size_t loop_end_ip = find_matching_bracket(block_code, ip);
                std::string loop_body_code = block_code.substr(ip + 1, loop_end_ip - ip - 1);

                llvm::BasicBlock* loop_cond_bb = llvm::BasicBlock::Create(TheContext, "loop.cond", F);
                llvm::BasicBlock* loop_body_bb = llvm::BasicBlock::Create(TheContext, "loop.body", F);
                llvm::BasicBlock* loop_after_bb = llvm::BasicBlock::Create(TheContext, "loop.after", F);

                Builder.CreateBr(loop_cond_bb);
                Builder.SetInsertPoint(loop_cond_bb);
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));
                Builder.CreateCondBr(is_zero, loop_after_bb, loop_body_bb);

                Builder.SetInsertPoint(loop_body_bb);
                compile_block(loop_body_code, func_name);
                Builder.CreateBr(loop_cond_bb);
                Builder.SetInsertPoint(loop_after_bb);

                ip = loop_end_ip;
            }
            break;
            case ']':
                break;
            case CUSTOM_CMD_FILE_OPEN:
            {
                llvm::Function* fopen_func = TheModule->getFunction("fopen");
                if (!fopen_func) {
                    llvm::FunctionType* fopen_ft = llvm::FunctionType::get(Builder.getInt8PtrTy(0), {Builder.getInt8PtrTy(0), Builder.getInt8PtrTy(0)}, false);
                    fopen_func = llvm::Function::Create(fopen_ft, llvm::Function::ExternalLinkage, "fopen", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* mode = Builder.CreateGlobalStringPtr("r+");
                llvm::Value* file_ptr = Builder.CreateCall(fopen_func, {current_dp, mode});
                Builder.CreateStore(file_ptr, FileHandle);
            }
            break;
            case CUSTOM_CMD_FILE_CLOSE:
            {
                llvm::Function* fclose_func = TheModule->getFunction("fclose");
                if (!fclose_func) {
                    llvm::FunctionType* fclose_ft = llvm::FunctionType::get(Builder.getInt32Ty(), {Builder.getInt8PtrTy(0)}, false);
                    fclose_func = llvm::Function::Create(fclose_ft, llvm::Function::ExternalLinkage, "fclose", TheModule.get());
                }
                llvm::Value* file_ptr = Builder.CreateLoad(Builder.getInt8PtrTy(0), FileHandle);
                Builder.CreateCall(fclose_func, {file_ptr});
                Builder.CreateStore(llvm::ConstantPointerNull::get(Builder.getInt8PtrTy(0)), FileHandle);
            }
            break;
            case CUSTOM_CMD_FILE_WRITE:
            {
                llvm::Function* fputc_func = TheModule->getFunction("fputc");
                if (!fputc_func) {
                    llvm::FunctionType* fputc_ft = llvm::FunctionType::get(Builder.getInt32Ty(), {Builder.getInt32Ty(), Builder.getInt8PtrTy(0)}, false);
                    fputc_func = llvm::Function::Create(fputc_ft, llvm::Function::ExternalLinkage, "fputc", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                llvm::Value* file_ptr = Builder.CreateLoad(Builder.getInt8PtrTy(0), FileHandle);
                Builder.CreateCall(fputc_func, {Builder.CreateZExt(loaded_val, Builder.getInt32Ty()), file_ptr});
            }
            break;
            case CUSTOM_CMD_FILE_READ:
            {
                llvm::Function* fgetc_func = TheModule->getFunction("fgetc");
                if (!fgetc_func) {
                    llvm::FunctionType* fgetc_ft = llvm::FunctionType::get(Builder.getInt32Ty(), {Builder.getInt8PtrTy(0)}, false);
                    fgetc_func = llvm::Function::Create(fgetc_ft, llvm::Function::ExternalLinkage, "fgetc", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* file_ptr = Builder.CreateLoad(Builder.getInt8PtrTy(0), FileHandle);
                llvm::Value* input_char = Builder.CreateCall(fgetc_func, {file_ptr});
                Builder.CreateStore(Builder.CreateTrunc(input_char, Builder.getInt8Ty()), current_dp);
            }
            break;
            case CUSTOM_CMD_SYSCALL:
            {
                llvm::Function* syscall_func = TheModule->getFunction("syscall");
                if (!syscall_func) {
                    llvm::FunctionType* syscall_ft = llvm::FunctionType::get(Builder.getInt64Ty(), {Builder.getInt64Ty(), Builder.getInt64Ty(), Builder.getInt64Ty(), Builder.getInt64Ty()}, false);
                    syscall_func = llvm::Function::Create(syscall_ft, llvm::Function::ExternalLinkage, "syscall", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                llvm::Value* syscall_num_ptr = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(0));
                llvm::Value* arg1_ptr = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(1));
                llvm::Value* arg2_ptr = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(2));
                llvm::Value* arg3_ptr = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(3));

                llvm::Value* syscall_num = Builder.CreateLoad(Builder.getInt64Ty(), syscall_num_ptr);
                llvm::Value* arg1 = Builder.CreateLoad(Builder.getInt64Ty(), arg1_ptr);
                llvm::Value* arg2 = Builder.CreateLoad(Builder.getInt64Ty(), arg2_ptr);
                llvm::Value* arg3 = Builder.CreateLoad(Builder.getInt64Ty(), arg3_ptr);

                Builder.CreateCall(syscall_func, {syscall_num, arg1, arg2, arg3});

                llvm::Value* new_dp = Builder.CreateGEP(Builder.getInt8Ty(), current_dp, Builder.getInt64(4));
                Builder.CreateStore(new_dp, DataPointer);
            }
            break;
            case CUSTOM_CMD_COND_START:
            {
                if (block_code.substr(ip + 1, 4) == "cond") {
                    ip += 5;
                    size_t cond_end_ip = find_matching_cond_end(block_code, ip);

                    llvm::BasicBlock* then_bb = llvm::BasicBlock::Create(TheContext, "cond.then", F);
                    llvm::BasicBlock* after_bb = llvm::BasicBlock::Create(TheContext, "cond.after", F);

                    llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                    llvm::Value* loaded_val = Builder.CreateLoad(Builder.getInt8Ty(), current_dp);
                    llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));

                    Builder.CreateCondBr(is_zero, after_bb, then_bb);
                    Builder.SetInsertPoint(then_bb);

                    std::string cond_block_content = block_code.substr(ip, cond_end_ip - ip);
                    compile_block(cond_block_content, func_name);
                    Builder.CreateBr(after_bb);
                    Builder.SetInsertPoint(after_bb);

                    ip = cond_end_ip;
                }
            }
            break;
            case CUSTOM_CMD_COND_BLOCK:
                break;
            case CUSTOM_CMD_RETURN:
                if (F->getReturnType()->isVoidTy()) {
                    Builder.CreateRetVoid();
                } else {
                    Builder.CreateRet(Builder.getInt32(0));
                }
                break;
            case CUSTOM_CMD_FUNC_CALL:
            {
                llvm::Value* current_dp = Builder.CreateLoad(Builder.getInt8PtrTy(0), DataPointer);
                std::string func_name_str = (char*)current_dp;
                llvm::Function* func_to_call = TheModule->getFunction(func_name_str);
                if (func_to_call) {
                    Builder.CreateCall(func_to_call);
                } else {
                    throw std::runtime_error("Unknown function");
                }
            }
            break;
            default:
                break;
        }
        ip++;
    }
    if (func_name.empty() == false) {
        Builder.CreateRetVoid();
    }
}

void compile(const std::string& code) {
    std::vector<llvm::Type*> params;
    llvm::FunctionType* FT = llvm::FunctionType::get(Builder.getInt32Ty(), params, false);
    llvm::Function* F = llvm::Function::Create(FT, llvm::Function::ExternalLinkage, "main", TheModule.get());
    llvm::BasicBlock* BB = llvm::BasicBlock::Create(TheContext, "entry", F);
    Builder.SetInsertPoint(BB);

    Tape = new llvm::GlobalVariable(*TheModule, llvm::ArrayType::get(Builder.getInt8Ty(), 30000), false,
                                      llvm::GlobalValue::InternalLinkage, llvm::ConstantAggregateZero::get(llvm::ArrayType::get(Builder.getInt8Ty(), 30000)),
                                      "tape");
    DataPointer = new llvm::GlobalVariable(*TheModule, Builder.getInt8PtrTy(0), false,
                                             llvm::GlobalValue::InternalLinkage, Builder.CreateInBoundsGEP(Tape->getValueType(), Tape, {Builder.getInt64(0), Builder.getInt64(0)}),
                                             "dp");
    FileHandle = new llvm::GlobalVariable(*TheModule, Builder.getInt8PtrTy(0), false,
                                          llvm::GlobalValue::InternalLinkage, llvm::ConstantPointerNull::get(Builder.getInt8PtrTy(0)),
                                          "file_handle");

    size_t ip = 0;
    while (ip < code.length()) {
        switch (code[ip]) {
            case '>':
            case '<':
            case '+':
            case '-':
            case '.':
            case ',':
            case '[':
            case ']':
            case CUSTOM_CMD_FILE_OPEN:
            case CUSTOM_CMD_FILE_CLOSE:
            case CUSTOM_CMD_FILE_WRITE:
            case CUSTOM_CMD_FILE_READ:
            case CUSTOM_CMD_SYSCALL:
            case CUSTOM_CMD_COND_START:
            case CUSTOM_CMD_COND_BLOCK:
            case CUSTOM_CMD_FUNC_CALL:
            case CUSTOM_CMD_RETURN:
                compile_block(code.substr(ip, 1), "");
                break;
            case CUSTOM_CMD_FUNC_START:
            {
                size_t brace_counter = 1;
                while (brace_counter > 0 && ip < code.length()) {
                    ip++;
                    if (code[ip] == CUSTOM_CMD_FUNC_START) brace_counter++;
                    if (code[ip] == CUSTOM_CMD_FUNC_END) brace_counter--;
                }
            }
            break;
            default:
                break;
        }
        ip++;
    }

    Builder.CreateRet(Builder.getInt32(0));
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <bf_file>\n";
        return 1;
    }

    TheModule = std::make_unique<llvm::Module>("bfcom", TheContext);

    std::string code = read_file_to_string(argv[1]);
    std::string preprocessed_code = preprocess_code(code);

    register_functions(preprocessed_code);

    for (auto const& [name, func_code] : FunctionCode) {
        compile_block(func_code, name);
    }
    
    compile(preprocessed_code);

    llvm::verifyModule(*TheModule);
    TheModule->print(llvm::outs(), nullptr);

    return 0;
}
