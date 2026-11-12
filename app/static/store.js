'use strict';
const $=id=>document.getElementById(id);
const CART=new Map();
let catalog=[];
const money=c=>'$'+(c/100).toFixed(2);
function toast(message){$('toast').textContent=message;$('toast').hidden=false;clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>$('toast').hidden=true,5500)}
async function request(path,options={}){
  const response=await fetch('/target/store/api/'+path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});
  let body;try{body=await response.json()}catch{body={detail:'Unexpected response'}}
  if(!response.ok)throw Error(body.detail||body.reason||body.message||'HTTP '+response.status);
  return body;
}
function make(tag,cls,text){let el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;}
function render(items){let grid=$('products');grid.replaceChildren();if(!items.length){grid.append(make('p','', 'No matching products.'));return;}
  items.forEach(p=>{let card=make('article','product'), art=make('div','product-art',p.emoji),body=make('div','product-info');
  body.append(make('span','category',p.category),make('h3','',p.name));let row=make('div','pricebuy');row.append(make('strong','',money(p.price_cents)));
  let button=make('button','','Add to cart +');button.onclick=()=>{CART.set(p.id,Math.min(10,(CART.get(p.id)||0)+1));updateCart();toast(p.name+' added to demo cart')};row.append(button);body.append(row);card.append(art,body);grid.append(card)});
}
function updateCart(){const items=$('cartItems');items.replaceChildren();let sum=0,n=0;for(const [id,quantity] of CART){const p=catalog.find(x=>x.id===id);if(!p)continue;n+=quantity;sum+=p.price_cents*quantity;let line=make('div','cartitem');let icon=make('span','mini',p.emoji),detail=make('div');detail.append(make('strong','',p.name),make('small','',quantity+' × '+money(p.price_cents)));let remove=make('button','','Remove');remove.onclick=()=>{CART.delete(id);updateCart()};line.append(icon,detail,remove);items.append(line)}if(!n)items.append(make('p','', 'Your demo cart is empty.'));$('total').textContent=money(sum);$('cartCount').textContent=String(n);$('checkout').disabled=n===0;}
function showCart(open){$('cartPanel').classList.toggle('open',open);$('cartPanel').setAttribute('aria-hidden',!open);$('overlay').hidden=!open;}
$('cartButton').onclick=()=>showCart(true);$('closeCart').onclick=()=>showCart(false);$('overlay').onclick=()=>showCart(false);
$('search').addEventListener('input',e=>{const q=e.target.value.trim().toLowerCase();render(catalog.filter(p=>p.name.toLowerCase().includes(q)||p.category.toLowerCase().includes(q)))});
$('checkout').onclick=async()=>{const items=[...CART].map(([product_id,quantity])=>({product_id,quantity}));if(!items.length)return;try{const result=await request('checkout',{method:'POST',body:JSON.stringify({items})});CART.clear();updateCart();showCart(false);toast('Dummy order '+result.order_id+' created · '+money(result.total_cents)+' · no payment')}catch(e){toast('Checkout failed: '+e.message)}};
async function demoLogin(wrong=false){try{const response=await fetch('/target/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('loginUser').value,password:wrong?'intentionally-wrong':$('loginPass').value})});const data=await response.json();$('labResult').textContent=JSON.stringify({status:response.status,...data},null,2);toast('Login test HTTP '+response.status)}catch(e){toast('Test failed: '+e.message)}}
$('login').onclick=()=>demoLogin(false);$('wrongLogin').onclick=()=>demoLogin(true);
$('slow').onclick=async()=>{const start=performance.now();try{const data=await request('slow?ms=200');$('labResult').textContent=JSON.stringify({...data,observed_ms:Math.round(performance.now()-start)},null,2)}catch(e){$('labResult').textContent=e.message}};
$('download').onclick=async()=>{try{const response=await fetch('/target/download?mb=1');if(!response.ok)throw Error('HTTP '+response.status);const data=await response.blob();const url=URL.createObjectURL(data);const link=document.createElement('a');link.href=url;link.download='koolab-demo.bin';link.click();setTimeout(()=>URL.revokeObjectURL(url),5000);$('labResult').textContent='Downloaded '+data.size+' bytes from protected application.'}catch(e){$('labResult').textContent=e.message}};
(async()=>{try{const data=await request('products');catalog=data.items;render(catalog);updateCart()}catch(e){$('products').textContent='Unable to load catalog: '+e.message;toast('WAF or IP ban may be blocking the store: '+e.message)}})();
