#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <stack>

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

void compile_block(const std::string& block_code);

void compile(const std::string& code) {
    std::vector<llvm::Type*> params;
    llvm::FunctionType* FT = llvm::FunctionType::get(llvm::Type::getInt32Ty(TheContext), params, false);
    llvm::Function* F = llvm::Function::Create(FT, llvm::Function::ExternalLinkage, "main", TheModule.get());
    llvm::BasicBlock* BB = llvm::BasicBlock::Create(TheContext, "entry", F);
    Builder.SetInsertPoint(BB);

    Tape = new llvm::GlobalVariable(*TheModule, llvm::ArrayType::get(llvm::Type::getInt8Ty(TheContext), 30000), false,
                                      llvm::GlobalValue::InternalLinkage, llvm::ConstantAggregateZero::get(llvm::ArrayType::get(llvm::Type::getInt8Ty(TheContext), 30000)),
                                      "tape");
    DataPointer = new llvm::GlobalVariable(*TheModule, llvm::PointerType::get(llvm::Type::getInt8Ty(TheContext), 0), false,
                                             llvm::GlobalValue::InternalLinkage, Builder.CreateInBoundsGEP(Tape->getValueType(), Tape, {Builder.getInt64(0), Builder.getInt64(0)}),
                                             "dp");

    size_t ip = 0;
    while (ip < code.length()) {
        switch (code[ip]) {
            case '>':
                {
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* new_dp = Builder.CreateGEP(llvm::Type::getInt8Ty(TheContext), current_dp, Builder.getInt64(1));
                    Builder.CreateStore(new_dp, DataPointer);
                }
                break;
            case '<':
                {
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* new_dp = Builder.CreateGEP(llvm::Type::getInt8Ty(TheContext), current_dp, Builder.getInt64(-1));
                    Builder.CreateStore(new_dp, DataPointer);
                }
                break;
            case '+':
                {
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                    llvm::Value* inc_val = Builder.CreateAdd(loaded_val, Builder.getInt8(1));
                    Builder.CreateStore(inc_val, current_dp);
                }
                break;
            case '-':
                {
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                    llvm::Value* dec_val = Builder.CreateSub(loaded_val, Builder.getInt8(1));
                    Builder.CreateStore(dec_val, current_dp);
                }
                break;
            case '.':
                {
                    llvm::Function* putchar_func = TheModule->getFunction("putchar");
                    if (!putchar_func) {
                        llvm::FunctionType* putchar_ft = llvm::FunctionType::get(llvm::Type::getInt32Ty(TheContext), {llvm::Type::getInt32Ty(TheContext)}, false);
                        putchar_func = llvm::Function::Create(putchar_ft, llvm::Function::ExternalLinkage, "putchar", TheModule.get());
                    }
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                    Builder.CreateCall(putchar_func, {Builder.CreateZExt(loaded_val, llvm::Type::getInt32Ty(TheContext))});
                }
                break;
            case ',':
                {
                    llvm::Function* getchar_func = TheModule->getFunction("getchar");
                    if (!getchar_func) {
                        llvm::FunctionType* getchar_ft = llvm::FunctionType::get(llvm::Type::getInt32Ty(TheContext), {}, false);
                        getchar_func = llvm::Function::Create(getchar_ft, llvm::Function::ExternalLinkage, "getchar", TheModule.get());
                    }
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* input_char = Builder.CreateCall(getchar_func);
                    Builder.CreateStore(Builder.CreateTrunc(input_char, llvm::Type::getInt8Ty(TheContext)), current_dp);
                }
                break;
            case '[':
                {
                    llvm::BasicBlock* loop_cond_bb = llvm::BasicBlock::Create(TheContext, "loop.cond", F);
                    llvm::BasicBlock* loop_body_bb = llvm::BasicBlock::Create(TheContext, "loop.body", F);
                    llvm::BasicBlock* loop_after_bb = llvm::BasicBlock::Create(TheContext, "loop.after", F);

                    Builder.CreateBr(loop_cond_bb);
                    Builder.SetInsertPoint(loop_cond_bb);
                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                    llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));
                    Builder.CreateCondBr(is_zero, loop_after_bb, loop_body_bb);

                    Builder.SetInsertPoint(loop_body_bb);

                    std::stack<size_t> loop_stack;
                    loop_stack.push(ip);
                    size_t loop_start_ip = ip;

                    while(!loop_stack.empty() && ip < code.length()){
                        ip++;
                        if(code[ip] == '['){
                            loop_stack.push(ip);
                        } else if(code[ip] == ']'){
                            loop_stack.pop();
                        }
                    }

                    Builder.CreateBr(loop_cond_bb);
                    Builder.SetInsertPoint(loop_after_bb);
                }
                break;
            case ']':
                break;
            case CUSTOM_CMD_COND_START:
                if (code.substr(ip + 1, 4) == "cond") {
                    ip += 5;
                    size_t cond_end_ip = find_matching_cond_end(code, ip);

                    llvm::BasicBlock* then_bb = llvm::BasicBlock::Create(TheContext, "cond.then", F);
                    llvm::BasicBlock* after_bb = llvm::BasicBlock::Create(TheContext, "cond.after", F);

                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");

                    llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));

                    Builder.CreateCondBr(is_zero, after_bb, then_bb);

                    Builder.SetInsertPoint(then_bb);

                    std::string cond_block_code = code.substr(ip, cond_end_ip - ip);
                    compile_block(cond_block_code);

                    Builder.CreateBr(after_bb);

                    Builder.SetInsertPoint(after_bb);

                    ip = cond_end_ip;
                }
                break;
            default:
                break;
        }
        ip++;
    }

    Builder.CreateRet(Builder.getInt32(0));
}

void compile_block(const std::string& block_code) {
    size_t ip = 0;
    while(ip < block_code.length()){
        switch(block_code[ip]){
            case '>':
            {
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* new_dp = Builder.CreateGEP(llvm::Type::getInt8Ty(TheContext), current_dp, Builder.getInt64(1));
                Builder.CreateStore(new_dp, DataPointer);
            }
            break;
            case '<':
            {
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* new_dp = Builder.CreateGEP(llvm::Type::getInt8Ty(TheContext), current_dp, Builder.getInt64(-1));
                Builder.CreateStore(new_dp, DataPointer);
            }
            break;
            case '+':
            {
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                llvm::Value* inc_val = Builder.CreateAdd(loaded_val, Builder.getInt8(1));
                Builder.CreateStore(inc_val, current_dp);
            }
            break;
            case '-':
            {
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                llvm::Value* dec_val = Builder.CreateSub(loaded_val, Builder.getInt8(1));
                Builder.CreateStore(dec_val, current_dp);
            }
            break;
            case '.':
            {
                llvm::Function* putchar_func = TheModule->getFunction("putchar");
                if (!putchar_func) {
                    llvm::FunctionType* putchar_ft = llvm::FunctionType::get(llvm::Type::getInt32Ty(TheContext), {llvm::Type::getInt32Ty(TheContext)}, false);
                    putchar_func = llvm::Function::Create(putchar_ft, llvm::Function::ExternalLinkage, "putchar", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                Builder.CreateCall(putchar_func, {Builder.CreateZExt(loaded_val, llvm::Type::getInt32Ty(TheContext))});
            }
            break;
            case ',':
            {
                llvm::Function* getchar_func = TheModule->getFunction("getchar");
                if (!getchar_func) {
                    llvm::FunctionType* getchar_ft = llvm::FunctionType::get(llvm::Type::getInt32Ty(TheContext), {}, false);
                    getchar_func = llvm::Function::Create(getchar_ft, llvm::Function::ExternalLinkage, "getchar", TheModule.get());
                }
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* input_char = Builder.CreateCall(getchar_func);
                Builder.CreateStore(Builder.CreateTrunc(input_char, llvm::Type::getInt8Ty(TheContext)), current_dp);
            }
            break;
            case '[':
            {
                llvm::BasicBlock* loop_cond_bb = llvm::BasicBlock::Create(TheContext, "loop.cond", Builder.GetInsertBlock()->getParent());
                llvm::BasicBlock* loop_body_bb = llvm::BasicBlock::Create(TheContext, "loop.body", Builder.GetInsertBlock()->getParent());
                llvm::BasicBlock* loop_after_bb = llvm::BasicBlock::Create(TheContext, "loop.after", Builder.GetInsertBlock()->getParent());

                Builder.CreateBr(loop_cond_bb);
                Builder.SetInsertPoint(loop_cond_bb);
                llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");
                llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));
                Builder.CreateCondBr(is_zero, loop_after_bb, loop_body_bb);

                Builder.SetInsertPoint(loop_body_bb);

                std::stack<size_t> loop_stack;
                loop_stack.push(ip);
                size_t loop_start_ip = ip;
                std::string block_content = block_code.substr(ip + 1);

                while(!loop_stack.empty() && ip < block_code.length()){
                    ip++;
                    if(block_code[ip] == '['){
                        loop_stack.push(ip);
                    } else if(block_code[ip] == ']'){
                        loop_stack.pop();
                    }
                }
                block_content = block_content.substr(0, ip - loop_start_ip - 1);
                compile_block(block_content);

                Builder.CreateBr(loop_cond_bb);
                Builder.SetInsertPoint(loop_after_bb);
            }
            break;
            case ']':
                break;
            case CUSTOM_CMD_COND_START:
                if (block_code.substr(ip + 1, 4) == "cond") {
                    ip += 5;
                    size_t cond_end_ip = find_matching_cond_end(block_code, ip);

                    llvm::BasicBlock* then_bb = llvm::BasicBlock::Create(TheContext, "cond.then", Builder.GetInsertBlock()->getParent());
                    llvm::BasicBlock* after_bb = llvm::BasicBlock::Create(TheContext, "cond.after", Builder.GetInsertBlock()->getParent());

                    llvm::Value* current_dp = Builder.CreateLoad(llvm::PointerType::get(TheContext, 0), DataPointer, "current_dp");
                    llvm::Value* loaded_val = Builder.CreateLoad(llvm::Type::getInt8Ty(TheContext), current_dp, "loaded_val");

                    llvm::Value* is_zero = Builder.CreateICmpEQ(loaded_val, Builder.getInt8(0));

                    Builder.CreateCondBr(is_zero, after_bb, then_bb);

                    Builder.SetInsertPoint(then_bb);

                    std::string cond_block_content = block_code.substr(ip, cond_end_ip - ip);
                    compile_block(cond_block_content);

                    Builder.CreateBr(after_bb);

                    Builder.SetInsertPoint(after_bb);

                    ip = cond_end_ip;
                }
                break;
            default:
                break;
        }
        ip++;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <bf_file>\n";
        return 1;
    }

    TheModule = std::make_unique<llvm::Module>("bfcom", TheContext);

    std::string code = read_file_to_string(argv[1]);
    std::string preprocessed_code = preprocess_code(code);

    compile(preprocessed_code);

    llvm::verifyModule(*TheModule);
    TheModule->print(llvm::outs(), nullptr);

    return 0;
}
