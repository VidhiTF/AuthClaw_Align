"use client";

import { useState, useRef, useEffect } from 'react';
import { Bot, Send, User, Loader2, Sparkles } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { apiClient } from '@/lib/api-client';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { motion, AnimatePresence } from 'framer-motion';

type Message = {
  role: 'user' | 'assistant' | 'system';
  content: string;
};

type ApiError = {
  response?: {
    data?: {
      detail?: string;
    };
  };
};

type MarkdownCodeProps = React.ComponentProps<'code'> & {
  inline?: boolean;
};

type MarkdownAnchorProps = React.ComponentProps<'a'>;
type MarkdownStrongProps = React.ComponentProps<'strong'>;

const initialMessage: Message = {
  role: 'assistant',
  content: 'Hello! I am your **AuthClaw AI Assistant**. I can help you analyze policy violations, explain compliance scores, query audit logs, or suggest remediation steps.\n\nHow can I help you today?',
};

function getInitialMessages(): Message[] {
  if (typeof window === 'undefined') {
    return [initialMessage];
  }
  try {
    const saved = localStorage.getItem('authclaw_agent_chat_history');
    return saved ? JSON.parse(saved) as Message[] : [initialMessage];
  } catch (e) {
    console.error('Failed to load chat history', e);
    return [initialMessage];
  }
}

export default function AgentPage() {
  const [messages, setMessages] = useState<Message[]>(getInitialMessages);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Save to local storage whenever messages change
  useEffect(() => {
    try {
      // Don't save if it's just the default initial message
      if (messages.length > 1) {
        localStorage.setItem('authclaw_agent_chat_history', JSON.stringify(messages));
      }
    } catch (e) {
      console.error('Failed to save chat history', e);
    }
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = { role: 'user', content: input };
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput('');
    setIsLoading(true);

    try {
      // Create payload without the initial welcome message, only real history
      const payloadMessages = newMessages.filter(m => m.role !== 'assistant' || !m.content.includes('Hello! I am your **AuthClaw AI Assistant**'));
      
      const response = await apiClient.post('/ai/chat', { messages: payloadMessages });
      
      if (response.data && response.data.status === 'success') {
        const reply = response.data.data;
        setMessages([...newMessages, reply]);
      } else {
        throw new Error('Invalid response from agent');
      }
    } catch (error: unknown) {
      const apiError = error as ApiError;
      const errorMsg = apiError.response?.data?.detail || 'I encountered an error connecting to the intelligence backend. Please try again later.';
      toast.error(apiError.response?.data?.detail ? 'Agent Error' : 'Failed to communicate with agent');
      setMessages([...newMessages, { role: 'assistant', content: `⚠️ **Error**\n\n${errorMsg}` }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([
      initialMessage
    ]);
    localStorage.removeItem('authclaw_agent_chat_history');
    toast.success('Chat history cleared');
  };

  return (
    <div className="flex flex-col h-[calc(100vh-10rem)] max-w-[1000px] mx-auto w-full">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4 mb-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-indigo-400" />
            AI Assistant
          </h2>
          <p className="text-sm text-neutral-400 mt-1">Chat with AuthClaw&apos;s intelligence engine to analyze your security posture.</p>
        </div>
        <Button 
          variant="ghost" 
          onClick={clearChat}
          disabled={messages.length <= 1}
          className="text-xs text-neutral-500 hover:text-white uppercase tracking-wider"
        >
          Clear History
        </Button>
      </div>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex-1 flex flex-col min-h-0">
        <Card className="glass-card flex-1 flex flex-col overflow-hidden shadow-2xl border-white/10">
          <CardContent className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6 flex flex-col scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
            <AnimatePresence initial={false}>
              {messages.map((message, i) => (
                <motion.div 
                  key={i} 
                  initial={{ opacity: 0, y: 10, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div className={`flex max-w-[85%] rounded-2xl p-5 gap-4 shadow-sm ${message.role === 'user' ? 'bg-indigo-600/90 text-white ml-8 rounded-tr-sm border border-indigo-500/50' : 'bg-black/40 border border-white/5 text-neutral-200 mr-8 rounded-tl-sm backdrop-blur-sm'}`}>
                    {message.role === 'assistant' && (
                      <div className="mt-0.5 shrink-0 bg-indigo-500/10 p-2 rounded-lg border border-indigo-500/20 h-fit">
                        <Bot className="w-5 h-5 text-indigo-400" />
                      </div>
                    )}
                    
                    <div className="prose prose-sm prose-invert max-w-none w-full leading-relaxed">
                      <ReactMarkdown 
                        remarkPlugins={[remarkGfm]}
                        components={{
                          code({ inline, className, children, ...props }: MarkdownCodeProps) {
                            return !inline ? (
                              <div className="bg-black/60 rounded-md p-3 my-2 border border-white/5 overflow-x-auto text-xs font-mono text-emerald-400">
                                <code className={className} {...props}>
                                  {children}
                                </code>
                              </div>
                            ) : (
                              <code className="bg-white/10 rounded px-1.5 py-0.5 text-xs font-mono text-amber-300" {...props}>
                                {children}
                              </code>
                            )
                          },
                          a({ children, href, ...props }: MarkdownAnchorProps) {
                            return <a href={href} className="text-blue-400 hover:text-blue-300 underline underline-offset-2" target="_blank" rel="noreferrer" {...props}>{children}</a>
                          },
                          strong({ children, ...props }: MarkdownStrongProps) {
                            return <strong className="font-semibold text-white" {...props}>{children}</strong>
                          }
                        }}
                      >
                        {message.content}
                      </ReactMarkdown>
                    </div>

                    {message.role === 'user' && (
                      <div className="mt-0.5 shrink-0 bg-black/20 p-2 rounded-lg h-fit">
                        <User className="w-5 h-5 text-white" />
                      </div>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            
            {isLoading && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex justify-start">
                <div className="flex items-center rounded-2xl rounded-tl-sm p-5 gap-4 bg-black/40 border border-white/5 text-neutral-400 backdrop-blur-sm max-w-[85%]">
                  <div className="bg-indigo-500/10 p-2 rounded-lg border border-indigo-500/20">
                    <Sparkles className="w-5 h-5 text-indigo-400 animate-pulse" />
                  </div>
                  <div className="flex space-x-1.5 items-center h-5 px-2">
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                    <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                  </div>
                </div>
              </motion.div>
            )}
            <div ref={messagesEndRef} className="h-px w-full" />
          </CardContent>
          
          <div className="p-4 sm:p-5 bg-black/60 border-t border-white/5 backdrop-blur-md">
            <div className="relative flex items-end gap-3 bg-white/[0.03] border border-white/10 rounded-xl p-2 focus-within:border-indigo-500/50 focus-within:bg-white/[0.05] transition-all">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about policy violations, investigate an audit log..."
                className="bg-transparent border-0 text-neutral-100 flex-1 focus-visible:ring-0 shadow-none text-base h-11 px-3"
                disabled={isLoading}
              />
              <Button 
                onClick={handleSend} 
                aria-label="Send message"
                disabled={isLoading || !input.trim()} 
                className="bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg h-11 px-4 shadow-lg shrink-0 transition-all active:scale-95 disabled:opacity-50"
              >
                {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
              </Button>
            </div>
            <div className="mt-2 text-center">
              <p className="text-[10px] text-neutral-500 uppercase tracking-wider">AI responses may be inaccurate. Verify important security information.</p>
            </div>
          </div>
        </Card>
      </motion.div>
    </div>
  );
}
